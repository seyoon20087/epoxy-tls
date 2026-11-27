//! Password protocol extension.
//!
//! **Passwords are sent in plain text!!**
//!
//! See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)
use std::collections::HashMap;

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{Role, WispError};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

/// ID of password protocol extension.
pub const PASSWORD_PROTOCOL_EXTENSION_ID: u8 = 0x02;

/// Password protocol extension.
///
/// **Passwords are sent in plain text!!**
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)
#[derive(Debug, Clone)]
pub enum PasswordProtocolExtension {
	/// Password protocol extension before the client INFO packet has been received.
	ServerBeforeClientInfo {
		/// Whether this authentication method is required.
		required: bool,
	},
	/// Password protocol extension after the client INFO packet has been received.
	ServerAfterClientInfo {
		/// The client's chosen user.
		chosen_user: String,
		/// The client's chosen password
		chosen_password: String,
	},

	/// Password protocol extension before the server INFO has been received.
	ClientBeforeServerInfo,
	/// Password protocol extension after the server INFO has been received.
	ClientAfterServerInfo {
		/// The user to send to the server.
		user: String,
		/// The password to send to the user.
		password: String,
	},
}

impl PasswordProtocolExtension {
	/// ID of password protocol extension.
	pub const ID: u8 = PASSWORD_PROTOCOL_EXTENSION_ID;
}

#[async_trait]
impl ProtocolExtension for PasswordProtocolExtension {
	fn get_id(&self) -> u8 {
		PASSWORD_PROTOCOL_EXTENSION_ID
	}

	fn encode(&self) -> Bytes {
		match self {
			Self::ServerBeforeClientInfo { required } => {
				let mut out = BytesMut::with_capacity(1);
				out.put_u8(u8::from(*required));
				out.freeze()
			}
			Self::ClientAfterServerInfo { user, password } => {
				let mut out = BytesMut::with_capacity(1 + 2 + user.len() + password.len());
				out.put_u8(user.len().try_into().unwrap());
				out.extend_from_slice(user.as_bytes());
				out.extend_from_slice(password.as_bytes());
				out.freeze()
			}

			Self::ServerAfterClientInfo { .. } | Self::ClientBeforeServerInfo => Bytes::new(),
		}
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(self.clone())
	}
}

/// Compare without short-circuiting on the first differing byte, so response timing doesn't
/// reveal how much of a guessed password was right. (The length still leaks, which is fine.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
	std::hint::black_box(diff) == 0
}

/// Password protocol extension builder.
///
/// **Passwords are sent in plain text!!**
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)
pub enum PasswordProtocolExtensionBuilder {
	/// Password protocol extension builder before the client INFO has been received.
	ServerBeforeClientInfo {
		/// The user+password combinations to verify the client with.
		users: HashMap<String, String>,
		/// Whether this authentication method is required.
		required: bool,
	},
	/// Password protocol extension builder after the client INFO has been received.
	ServerAfterClientInfo {
		/// The user+password combinations to verify the client with.
		users: HashMap<String, String>,
		/// Whether this authentication method is required.
		required: bool,
	},

	/// Password protocol extension builder before the server INFO has been received.
	ClientBeforeServerInfo {
		/// The credentials to send to the server.
		creds: Option<(String, String)>,
	},
	/// Password protocol extension builder after the server INFO has been received.
	ClientAfterServerInfo {
		/// The credentials to send to the server.
		creds: Option<(String, String)>,
		/// Whether this authentication method is required.
		required: bool,
	},
}

impl PasswordProtocolExtensionBuilder {
	/// ID of password protocol extension.
	pub const ID: u8 = PASSWORD_PROTOCOL_EXTENSION_ID;

	/// Create a new server variant of the password protocol extension.
	pub fn new_server(users: HashMap<String, String>, required: bool) -> Self {
		Self::ServerBeforeClientInfo { users, required }
	}

	/// Create a new client variant of the password protocol extension with a username and password.
	pub fn new_client(creds: Option<(String, String)>) -> Self {
		Self::ClientBeforeServerInfo { creds }
	}

	/// Get whether this authentication method is required. Could return None if the server has not
	/// sent the password protocol extension.
	pub fn is_required(&self) -> Option<bool> {
		match self {
			Self::ServerBeforeClientInfo { required, .. }
			| Self::ServerAfterClientInfo { required, .. }
			| Self::ClientAfterServerInfo { required, .. } => Some(*required),
			Self::ClientBeforeServerInfo { .. } => None,
		}
	}

	/// Set the credentials sent to the server, if this is a client variant.
	pub fn set_creds(&mut self, credentials: (String, String)) {
		match self {
			Self::ClientBeforeServerInfo { creds } | Self::ClientAfterServerInfo { creds, .. } => {
				*creds = Some(credentials);
			}
			Self::ServerBeforeClientInfo { .. } | Self::ServerAfterClientInfo { .. } => {}
		}
	}
}

impl ProtocolExtensionBuilder for PasswordProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		PASSWORD_PROTOCOL_EXTENSION_ID
	}

	fn build_to_extension(&mut self, _role: Role) -> Result<AnyProtocolExtension, WispError> {
		match self {
			Self::ServerBeforeClientInfo { users: _, required } => {
				Ok(PasswordProtocolExtension::ServerBeforeClientInfo {
					required: *required,
				}
				.into())
			}
			Self::ServerAfterClientInfo { .. } | Self::ClientBeforeServerInfo { .. } => {
				Err(WispError::ExtensionImplNotSupported)
			}
			Self::ClientAfterServerInfo { creds, .. } => {
				let (user, password) = creds.clone().ok_or(WispError::PasswordExtensionNoCreds)?;
				Ok(PasswordProtocolExtension::ClientAfterServerInfo { user, password }.into())
			}
		}
	}

	fn build_from_bytes(
		&mut self,
		mut bytes: Bytes,
		_role: Role,
	) -> Result<AnyProtocolExtension, WispError> {
		match self {
			Self::ServerBeforeClientInfo { users, required } => {
				if bytes.remaining() < 1 {
					return Err(WispError::PacketTooSmall);
				}
				let user_len = bytes.get_u8();
				if bytes.remaining() < user_len as usize {
					return Err(WispError::PacketTooSmall);
				}

				let user = std::str::from_utf8(&bytes.split_to(user_len as usize))?.to_string();
				let password = std::str::from_utf8(&bytes)?.to_string();

				let valid = users
					.get(&user)
					.is_some_and(|x| constant_time_eq(x.as_bytes(), password.as_bytes()));

				*self = Self::ServerAfterClientInfo {
					users: users.clone(),
					required: *required,
				};

				if valid {
					Ok(PasswordProtocolExtension::ServerAfterClientInfo {
						chosen_user: user,
						chosen_password: password,
					}
					.into())
				} else {
					Err(WispError::PasswordExtensionCredsInvalid)
				}
			}
			Self::ClientBeforeServerInfo { creds } => {
				if bytes.remaining() < 1 {
					return Err(WispError::PacketTooSmall);
				}
				let required = bytes.get_u8() != 0;

				*self = Self::ClientAfterServerInfo {
					creds: creds.clone(),
					required,
				};

				Ok(PasswordProtocolExtension::ClientBeforeServerInfo.into())
			}
			Self::ClientAfterServerInfo { .. } | Self::ServerAfterClientInfo { .. } => {
				Err(WispError::ExtensionImplNotSupported)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use bytes::Bytes;

	use super::*;

	fn server() -> PasswordProtocolExtensionBuilder {
		PasswordProtocolExtensionBuilder::new_server(
			HashMap::from([("user".to_string(), "pass".to_string())]),
			true,
		)
	}

	#[test]
	fn short_client_info_is_an_error_not_a_panic() {
		for bytes in [&b""[..], &[0xFF][..], &[5, b'a'][..]] {
			let res = server().build_from_bytes(Bytes::copy_from_slice(bytes), Role::Server);
			assert!(matches!(res, Err(WispError::PacketTooSmall)), "{bytes:?}");
		}
		let res = PasswordProtocolExtensionBuilder::new_client(None)
			.build_from_bytes(Bytes::new(), Role::Client);
		assert!(matches!(res, Err(WispError::PacketTooSmall)));
	}

	#[test]
	fn valid_and_invalid_creds() {
		let ok = server().build_from_bytes(Bytes::from_static(b"\x04userpass"), Role::Server);
		assert!(ok.is_ok());
		let bad = server().build_from_bytes(Bytes::from_static(b"\x04userwrong"), Role::Server);
		assert!(matches!(bad, Err(WispError::PasswordExtensionCredsInvalid)));
	}
}
