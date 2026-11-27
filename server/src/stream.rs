use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::FromStr,
};

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::BytesMut;
use cfg_if::cfg_if;
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::debug;
use regex::RegexSet;
use tokio::net::{TcpStream, UdpSocket};
use tokio_websockets::{CloseCode, Message, Payload, WebSocketStream};
use wisp_mux::{
	packet::{ConnectPacket, StreamType},
	stream::MuxStream,
};

use crate::{
	route::WispStreamWrite,
	ws_limit::{PingFlood, PingLimiter},
	CONFIG, RESOLVER,
};

fn match_addr(str: &str, allowed: &RegexSet, blocked: &RegexSet) -> bool {
	blocked.is_match(str) && !allowed.is_match(str)
}

fn allowed_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.allowed_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.allowed_udp_hosts(),
		StreamType::Other(_) => unreachable!(),
	}
}

fn blocked_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.blocked_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.blocked_udp_hosts(),
		StreamType::Other(_) => unreachable!(),
	}
}

pub enum ClientStream {
	Tcp(TcpStream),
	Udp(UdpSocket),
	#[cfg(feature = "twisp")]
	Pty(tokio::process::Child, pty_process::Pty),
	Wispnet(MuxStream<WispStreamWrite>, String),

	NoResolvedAddrs,
	Blocked,
	Invalid,
}

// taken from rust 1.82.0
fn ipv4_is_global(addr: Ipv4Addr) -> bool {
	!(addr.octets()[0] == 0 // "This network"
            || addr.is_private()
            || (addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)) // || addr.is_shared()
            || addr.is_loopback()
            || addr.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // .9 and .10 are documented as globally reachable so they're excluded
            || (
                addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0
                && addr.octets()[3] != 9 && addr.octets()[3] != 10
            )
            || addr.is_documentation()
            || (addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18) // || addr.is_benchmarking()
            || (addr.octets()[0] & 240 == 240) // || addr.is_reserved()
            || addr.is_broadcast())
}
fn ipv6_is_global(addr: Ipv6Addr) -> bool {
	!(
		addr.is_unspecified()
            || addr.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(addr.segments(), [0x2002, _, _, _, _, _, _, _])
            || ((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)) // || addr.is_documentation()
            || (addr.segments()[0] & 0xfe00) == 0xfc00 // addr.is_unique_local()
            || (addr.segments()[0] & 0xffc0) == 0xfe80 // addr.is_unicast_link_local()
	)
}

/// Addresses that reach this machine: loopback, plus the unspecified address (`0.0.0.0` / `::`),
/// which Linux treats as "connect to self".
///
/// Callers must pass a canonical address (see [`IpAddr::to_canonical`]) so IPv4-mapped IPv6
/// forms like `::ffff:127.0.0.1` are caught too.
fn is_local_host(addr: IpAddr) -> bool {
	addr.is_loopback() || addr.is_unspecified()
}

/// Whether `host` is an IP address in any form a resolver might accept: plain, bracketed IPv6
/// (`[::1]`), or the legacy `inet_aton` shorthands the system resolver understands
/// (`2130706433`, `0x7f.1`, `127.1`). Expects a lowercased host.
fn is_ip_literal(host: &str) -> bool {
	if IpAddr::from_str(host).is_ok() {
		return true;
	}
	if let Some(inner) = host.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
		if Ipv6Addr::from_str(inner).is_ok() {
			return true;
		}
	}
	let parts: Vec<&str> = host.split('.').collect();
	parts.len() <= 4
		&& parts.iter().all(|part| {
			if let Some(hex) = part.strip_prefix("0x") {
				!hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
			} else {
				!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
			}
		})
}

/// Normalize a hostname before matching it against host regexes, so `EXAMPLE.com.` can't slip
/// past a rule written for `example.com`. DNS names are case-insensitive and a trailing dot only
/// marks the name as fully qualified.
fn normalize_host(host: &str) -> String {
	host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}
/// The address whose class decides whether a connection is allowed. IPv6 forms that carry an
/// IPv4 address get checked as that IPv4 address:
/// - `::ffff:a.b.c.d` (IPv4-mapped)
/// - `64:ff9b::a.b.c.d` (well-known NAT64 prefix, so `64:ff9b::a00:5` can't reach `10.0.0.5`
///   through a NAT64 gateway)
/// - `::a.b.c.d` (deprecated IPv4-compatible; `::` and `::1` stay as they are)
///
/// The original address is still the one connected to.
fn filter_addr(addr: IpAddr) -> IpAddr {
	let IpAddr::V6(v6) = addr.to_canonical() else {
		return addr.to_canonical();
	};
	let seg = v6.segments();
	let embedded = Ipv4Addr::from(u32::from_be_bytes(
		v6.octets()[12..16].try_into().expect("slice is 4 bytes"),
	));
	match seg {
		[0x64, 0xff9b, 0, 0, 0, 0, _, _] => IpAddr::V4(embedded),
		[0, 0, 0, 0, 0, 0, _, _] if !v6.is_unspecified() && !v6.is_loopback() => {
			IpAddr::V4(embedded)
		}
		_ => IpAddr::V6(v6),
	}
}

fn is_global(addr: IpAddr) -> bool {
	match addr {
		IpAddr::V4(x) => ipv4_is_global(x),
		IpAddr::V6(x) => ipv6_is_global(x),
	}
}

pub enum ResolvedPacket {
	Valid(ConnectPacket),
	ValidWispnet(u32, ConnectPacket),
	NoResolvedAddrs,
	Blocked,
	Invalid,
}

impl ClientStream {
	pub async fn resolve(packet: ConnectPacket) -> anyhow::Result<ResolvedPacket> {
		if CONFIG.wisp.has_wispnet() && packet.host.ends_with(".wisp") {
			if let Some(wispnet_server) = packet.host.split(".wisp").next() {
				debug!("routing {:?} through wispnet", packet);
				let decoded = BASE64_STANDARD
					.decode(wispnet_server)
					.context("failed to decode wispnet server")?;
				let server_id = u32::from_str(
					&String::from_utf8(decoded).context("wispnet server was not a string")?,
				)
				.context("failed to parse wispnet server from string")?;
				return Ok(ResolvedPacket::ValidWispnet(server_id, packet));
			}
		}

		cfg_if! {
			if #[cfg(feature = "twisp")] {
				if let StreamType::Other(ty) = packet.stream_type {
					if ty == crate::handle::wisp::twisp::STREAM_TYPE && CONFIG.stream.allow_twisp && CONFIG.wisp.wisp_v2 {
						return Ok(ResolvedPacket::Valid(packet));
					}
					return Ok(ResolvedPacket::Invalid);
				}
			} else {
				if matches!(packet.stream_type, StreamType::Other(_)) {
					return Ok(ResolvedPacket::Invalid);
				}
			}
		}

		// after the wispnet and twisp branches: wispnet ids are case-sensitive base64 and a twisp
		// "host" is a command line
		let packet = ConnectPacket {
			host: normalize_host(&packet.host),
			..packet
		};

		if !CONFIG.stream.allow_udp && packet.stream_type == StreamType::Udp {
			return Ok(ResolvedPacket::Blocked);
		}

		if CONFIG
			.stream
			.blocked_ports()
			.iter()
			.any(|x| x.contains(&packet.port))
			&& !CONFIG
				.stream
				.allowed_ports()
				.iter()
				.any(|x| x.contains(&packet.port))
		{
			return Ok(ResolvedPacket::Blocked);
		}

		if is_ip_literal(&packet.host) {
			if !CONFIG.stream.allow_direct_ip {
				return Ok(ResolvedPacket::Blocked);
			}
		}

		if match_addr(
			&packet.host,
			allowed_set(packet.stream_type),
			blocked_set(packet.stream_type),
		) {
			return Ok(ResolvedPacket::Blocked);
		}

		// allow stream type whitelists through
		if match_addr(
			&packet.host,
			CONFIG.stream.allowed_hosts(),
			CONFIG.stream.blocked_hosts(),
		) && !allowed_set(packet.stream_type).is_match(&packet.host)
		{
			return Ok(ResolvedPacket::Blocked);
		}

		let packet = RESOLVER
			.resolve(packet.host)
			.await
			.context("failed to resolve hostname")?
			.filter(|x| CONFIG.server.resolve_ipv6 || x.is_ipv4())
			.map(|addr| {
				// connect to `::ffff:a.b.c.d` as plain IPv4
				let addr = addr.to_canonical();
				// check addresses with an embedded IPv4 address against the IPv4 rules
				let checked = filter_addr(addr);

				if is_local_host(checked) && !CONFIG.stream.allow_loopback {
					return ResolvedPacket::Blocked;
				}

				if checked.is_multicast() && !CONFIG.stream.allow_multicast {
					return ResolvedPacket::Blocked;
				}

				if (is_global(checked) && !CONFIG.stream.allow_global)
					|| (!is_global(checked) && !CONFIG.stream.allow_non_global)
				{
					return ResolvedPacket::Blocked;
				}

				ResolvedPacket::Valid(ConnectPacket {
					stream_type: packet.stream_type,
					host: addr.to_string(),
					port: packet.port,
				})
			})
			.next();

		Ok(packet.unwrap_or(ResolvedPacket::NoResolvedAddrs))
	}

	pub async fn connect(packet: ConnectPacket) -> anyhow::Result<Self> {
		match packet.stream_type {
			StreamType::Tcp => {
				let ipaddr =
					IpAddr::from_str(&packet.host).context("failed to parse hostname as ipaddr")?;
				let stream = TcpStream::connect(SocketAddr::new(ipaddr, packet.port))
					.await
					.with_context(|| format!("failed to connect to host {}", packet.host))?;

				if CONFIG.stream.tcp_nodelay {
					stream
						.set_nodelay(true)
						.context("failed to set tcp nodelay")?;
				}

				Ok(ClientStream::Tcp(stream))
			}
			StreamType::Udp => {
				if !CONFIG.stream.allow_udp {
					return Ok(ClientStream::Blocked);
				}

				let ipaddr =
					IpAddr::from_str(&packet.host).context("failed to parse hostname as ipaddr")?;

				let bind_addr = if ipaddr.is_ipv4() {
					SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0)
				} else {
					SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0)
				};

				let stream = UdpSocket::bind(bind_addr).await?;

				stream.connect(SocketAddr::new(ipaddr, packet.port)).await?;

				Ok(ClientStream::Udp(stream))
			}
			#[cfg(feature = "twisp")]
			StreamType::Other(crate::handle::wisp::twisp::STREAM_TYPE) => {
				if !CONFIG.stream.allow_twisp {
					return Ok(ClientStream::Blocked);
				}

				let cmdline: Vec<std::ffi::OsString> = shell_words::split(&packet.host)?
					.into_iter()
					.map(Into::into)
					.collect();
				let pty = pty_process::Pty::new()?;

				let Some((program, args)) = cmdline.split_first() else {
					return Ok(ClientStream::Invalid);
				};
				let cmd = pty_process::Command::new(program)
					.args(args)
					.spawn(&pty.pts()?)?;

				Ok(ClientStream::Pty(cmd, pty))
			}
			StreamType::Other(_) => Ok(ClientStream::Invalid),
		}
	}
}

pub enum WebSocketFrame {
	Data(BytesMut),
	Close,
	Ignore,
}

pub struct WebSocketStreamWrapper(pub WebSocketStream<TokioIo<Upgraded>>, pub PingLimiter);

impl WebSocketStreamWrapper {
	pub fn new(ws: WebSocketStream<TokioIo<Upgraded>>) -> Self {
		Self(ws, PingLimiter::default())
	}

	pub async fn read(&mut self) -> Option<anyhow::Result<WebSocketFrame>> {
		let frame = self.0.next().await?;
		match frame {
			Ok(frame) if frame.is_binary() || frame.is_text() => {
				Some(Ok(WebSocketFrame::Data(frame.into_payload().into())))
			}
			Ok(frame) if frame.is_close() => Some(Ok(WebSocketFrame::Close)),
			Ok(frame) if frame.is_ping() && !self.1.record() => Some(Err(PingFlood.into())),
			Ok(_) => Some(Ok(WebSocketFrame::Ignore)),
			Err(err) => Some(Err(err.into())),
		}
	}

	pub async fn write(&mut self, data: impl Into<Payload>) -> Result<(), tokio_websockets::Error> {
		self.0.send(Message::binary(data)).await
	}

	pub async fn close(
		&mut self,
		code: CloseCode,
		reason: &str,
	) -> Result<(), tokio_websockets::Error> {
		// `Message::close` panics on reasons over 123 bytes (which aborts the process in release),
		// and callers pass error strings we don't control
		let mut end = reason.len().min(123);
		while !reason.is_char_boundary(end) {
			end -= 1;
		}
		self.0.send(Message::close(Some(code), &reason[..end])).await?;
		self.0.close().await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn canon(s: &str) -> IpAddr {
		IpAddr::from_str(s).unwrap().to_canonical()
	}

	#[test]
	fn local_host_covers_unspecified_and_mapped_loopback() {
		for s in ["127.0.0.1", "127.8.9.10", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1", "::ffff:0.0.0.0"] {
			assert!(is_local_host(canon(s)), "{s}");
		}
		for s in ["1.1.1.1", "10.0.0.1", "::ffff:1.1.1.1", "2606:4700::1111"] {
			assert!(!is_local_host(canon(s)), "{s}");
		}
	}

	#[test]
	fn link_local_v6_is_not_global() {
		assert!(!is_global(canon("fe80::1")));
		assert!(!is_global(canon("febf::1")));
		assert!(!is_global(canon("fd00::1")));
		assert!(is_global(canon("2606:4700::1111")));
		// mapped addresses get the IPv4 rules once canonicalized
		assert!(!is_global(canon("::ffff:192.168.1.1")));
		assert!(is_global(canon("::ffff:1.1.1.1")));
	}

	#[test]
	fn embedded_ipv4_is_checked_as_ipv4() {
		let f = |s: &str| filter_addr(IpAddr::from_str(s).unwrap());
		assert_eq!(f("64:ff9b::a00:5"), canon("10.0.0.5"));
		assert_eq!(f("64:ff9b::7f00:1"), canon("127.0.0.1"));
		assert_eq!(f("::7f00:1"), canon("127.0.0.1"));
		assert_eq!(f("::ffff:192.168.1.1"), canon("192.168.1.1"));
		assert!(is_local_host(f("64:ff9b::7f00:1")));
		assert!(!is_global(f("64:ff9b::a9fe:a9fe")));
		assert!(is_global(f("64:ff9b::101:101")));
		// unchanged
		assert_eq!(f("::"), canon("::"));
		assert_eq!(f("::1"), canon("::1"));
		assert_eq!(f("2606:4700::1111"), canon("2606:4700::1111"));
		assert_eq!(f("1.1.1.1"), canon("1.1.1.1"));
	}

	#[test]
	fn ip_literal_forms() {
		for s in ["127.0.0.1", "::1", "[::1]", "2130706433", "0x7f.1", "127.1", "0x7f000001"] {
			assert!(is_ip_literal(s), "{s}");
		}
		for s in ["example.com", "deadbeef", "1.example", "0x.1", "1..2", "a.b.c.d.e"] {
			assert!(!is_ip_literal(s), "{s}");
		}
	}

	#[test]
	fn host_normalization() {
		assert_eq!(normalize_host("EXAMPLE.Com."), "example.com");
		assert_eq!(normalize_host("example.com"), "example.com");
		assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
	}
}
