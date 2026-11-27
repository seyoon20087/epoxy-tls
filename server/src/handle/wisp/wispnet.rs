use std::{
	collections::HashMap,
	sync::Arc,
	time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use log::debug;
use tokio::{select, sync::Mutex, time::timeout};
use uuid::Uuid;
use wisp_mux::{
	extensions::{
		AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder, ProtocolExtensionListExt,
	},
	packet::{CloseReason, ConnectPacket},
	stream::{MuxStream, MuxStreamRead, MuxStreamWrite},
	ws::{TransportRead, TransportWrite},
	ClientMux, Role, WispError, WispV2Handshake,
};

use crate::{
	route::{WispResult, WispStreamWrite},
	stream::ClientStream,
	CLIENTS,
};

struct WispnetClient {
	mux: Arc<ClientMux<WispStreamWrite>>,
	id: String,
	private: bool,
}

lazy_static! {
	static ref WISPNET_SERVERS: Mutex<HashMap<u32, WispnetClient>> = Mutex::new(HashMap::new());
}

// payload:
// client (acting like wisp server) sends a bool saying if it wants to be private or not
// server (acting like wisp client) sends a u32 client id
//
// packets:
// client sends a 0xF1 on stream id 0 with no body to probe
// server sends back a 0xF1 on stream id 0 with a body of a bunch of u32s for each public client

struct WispnetServerProtocolExtensionBuilder(u32);
impl WispnetServerProtocolExtensionBuilder {
	const ID: u8 = 0xF1;
}

#[async_trait]
impl ProtocolExtensionBuilder for WispnetServerProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn build_from_bytes(
		&mut self,
		mut bytes: Bytes,
		_: Role,
	) -> Result<AnyProtocolExtension, WispError> {
		if bytes.remaining() < 1 {
			return Err(WispError::PacketTooSmall);
		};
		Ok(WispnetServerProtocolExtension(self.0, bytes.get_u8() != 0).into())
	}

	fn build_to_extension(&mut self, _: Role) -> Result<AnyProtocolExtension, WispError> {
		Ok(WispnetServerProtocolExtension(self.0, false).into())
	}
}

#[derive(Debug, Copy, Clone)]
struct WispnetServerProtocolExtension(u32, pub bool);
impl WispnetServerProtocolExtension {
	const ID: u8 = 0xF1;
}

#[async_trait]
impl ProtocolExtension for WispnetServerProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}
	fn get_supported_packets(&self) -> &'static [u8] {
		&[Self::ID]
	}
	fn get_congestion_stream_types(&self) -> &'static [u8] {
		&[]
	}
	fn encode(&self) -> Bytes {
		let mut out = BytesMut::new();
		out.put_u32_le(self.0);
		out.freeze()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut dyn TransportRead,
		_: &mut dyn TransportWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		packet_type: u8,
		mut packet: Bytes,
		_: &mut dyn TransportRead,
		write: &mut dyn TransportWrite,
	) -> Result<(), WispError> {
		if packet_type == Self::ID {
			if packet.remaining() < 4 {
				return Err(WispError::PacketTooSmall);
			}
			let id = packet.get_u32_le();
			if id != 0 {
				return Err(WispError::InvalidStreamId(id));
			}

			let mut out = BytesMut::new();
			out.put_u8(Self::ID);
			out.put_u32_le(0);

			let locked = WISPNET_SERVERS.lock().await;
			for client in locked.iter() {
				if !client.1.private {
					out.put_u32_le(*client.0);
				}
			}
			drop(locked);

			write.send(out.into()).await?;
		}
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(*self)
	}
}

/// How long a wispnet peer gets to accept a new stream.
const WISPNET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn route_wispnet(server: u32, packet: ConnectPacket) -> Result<ClientStream> {
	// Copy what we need out and release the global lock *before* talking to the peer. A peer
	// that stops reading would otherwise leave `new_stream` pending with the lock held, freezing
	// wispnet routing, registration and cleanup for everyone.
	let Some((mux, id)) = WISPNET_SERVERS
		.lock()
		.await
		.get(&server)
		.map(|x| (x.mux.clone(), x.id.clone()))
	else {
		return Ok(ClientStream::NoResolvedAddrs);
	};

	let stream = timeout(
		WISPNET_CONNECT_TIMEOUT,
		mux.new_stream(packet.stream_type, packet.host, packet.port),
	)
	.await
	.context("wispnet server timed out")?
	.context("failed to connect to wispnet server")?;
	Ok(ClientStream::Wispnet(stream, id))
}

async fn copy_wisp(
	mut rx: MuxStreamRead<WispStreamWrite>,
	mut tx: MuxStreamWrite<WispStreamWrite>,
	#[cfg(feature = "speed-limit")] limiter: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) -> Result<()> {
	while let Some(data) = rx.next().await {
		let data = data?;

		#[cfg(feature = "speed-limit")]
		limiter.consume(data.len()).await;
		tx.send(data).await?;
	}
	Ok(())
}

pub async fn handle_stream(
	mux: MuxStream<WispStreamWrite>,
	wisp: MuxStream<WispStreamWrite>,
	mux_id: String,
	uuid: Uuid,
	resolved_stream: ConnectPacket,
	#[cfg(feature = "speed-limit")] read_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
	#[cfg(feature = "speed-limit")] write_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) {
	if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
		client
			.0
			.lock()
			.await
			.insert(uuid, (resolved_stream.clone(), resolved_stream));
	}

	let closer = mux.get_close_handle();

	let (muxread, muxwrite) = mux.into_split();
	let (wispread, wispwrite) = wisp.into_split();
	let _ = select! {
		x = copy_wisp(muxread, wispwrite, #[cfg(feature = "speed-limit")] write_limit) => x,
		x = copy_wisp(wispread, muxwrite, #[cfg(feature = "speed-limit")] read_limit) => x,
	};

	let _ = closer
		.close(closer.get_close_reason().unwrap_or(CloseReason::Unknown))
		.await;

	if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
		client.0.lock().await.remove(&uuid);
	}
}

async fn new_wispnet_id() -> u32 {
	let servers = WISPNET_SERVERS.lock().await;
	loop {
		#[expect(clippy::cast_possible_truncation)]
		let id = Uuid::new_v4().as_u128() as u32;
		if !servers.contains_key(&id) {
			return id;
		}
	}
}

pub async fn handle_wispnet(stream: WispResult, id: String) -> Result<()> {
	let (read, write) = stream;
	// Random rather than sequential: "private" servers are only hidden from the listing, so a
	// counter would let anyone reach them by trying 0, 1, 2, ... The protocol caps ids at u32.
	let net_id = new_wispnet_id().await;

	let extensions = vec![WispnetServerProtocolExtensionBuilder(net_id).into()];

	let (mux, fut) = tokio::time::timeout(super::HANDSHAKE_TIMEOUT, async {
		Box::pin(
			ClientMux::new(read, write, Some(WispV2Handshake::new(extensions)))
				.await
				.context("failed to create client multiplexor")?
				.with_required_extensions(&[WispnetServerProtocolExtension::ID]),
		)
		.await
		.context("wispnet client did not have wispnet extension")
	})
	.await
	.context("wispnet handshake timed out")??;

	let is_private = mux
		.get_extensions()
		.find_extension::<WispnetServerProtocolExtension>()
		.context("failed to find wispnet extension")?
		.1;

	let mut servers = WISPNET_SERVERS.lock().await;
	if servers.contains_key(&net_id) {
		// another peer registered the same random id during our handshake
		drop(servers);
		let _ = mux.close().await;
		anyhow::bail!("wispnet id collision");
	}
	servers.insert(
		net_id,
		WispnetClient {
			mux: Arc::new(mux),
			id: id.clone(),
			private: is_private,
		},
	);
	drop(servers);

	// probably the only time someone would do this
	let ret = fut.await;
	debug!("wispnet client id {:?} multiplexor result {:?}", id, ret);

	WISPNET_SERVERS.lock().await.remove(&net_id);

	Ok(())
}
