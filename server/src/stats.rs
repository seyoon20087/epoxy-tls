use std::{collections::HashMap, time::Duration};

use serde::Serialize;
use tokio::{sync::Mutex, time::Instant};
use wisp_mux::packet::{ConnectPacket, StreamType};

use crate::{CLIENTS, CONFIG};

fn format_stream_type(stream_type: StreamType) -> &'static str {
	match stream_type {
		StreamType::Tcp => "tcp",
		StreamType::Udp => "udp",
		#[cfg(feature = "twisp")]
		StreamType::Other(crate::handle::wisp::twisp::STREAM_TYPE) => "twisp",
		// reachable: wispnet routing forwards any stream type, and a panic here aborts the
		// whole server (panic = "abort") the next time stats are generated
		StreamType::Other(_) => "other",
	}
}

#[derive(Serialize)]
struct MemoryStats {
	active: usize,
	allocated: usize,
	mapped: usize,
	metadata: usize,
	resident: usize,
	retained: usize,
}

#[derive(Serialize)]
struct StreamStats {
	stream_type: String,
	requested: String,
	resolved: String,
}

impl From<(ConnectPacket, ConnectPacket)> for StreamStats {
	fn from(value: (ConnectPacket, ConnectPacket)) -> Self {
		Self {
			stream_type: format_stream_type(value.0.stream_type).to_string(),
			requested: format!("{}:{}", value.0.host, value.0.port),
			resolved: format!("{}:{}", value.1.host, value.1.port),
		}
	}
}

#[derive(Serialize)]
struct ClientStats {
	client_type: String,
	streams: HashMap<String, StreamStats>,
}

#[derive(Serialize)]
struct ServerStats {
	config: String,
	client_count: usize,
	#[serde(skip_serializing_if = "Option::is_none")]
	clients: Option<HashMap<String, ClientStats>>,
	memory: MemoryStats,
}

/// How long a generated stats report is reused.
const STATS_CACHE_TTL: Duration = Duration::from_secs(2);

/// Last report and when it was made. A tokio mutex so concurrent requests wait for one
/// generation instead of each taking the global `CLIENTS` lock.
static STATS_CACHE: Mutex<Option<(Instant, String)>> = Mutex::const_new(None);

/// Stats report, regenerated at most once per [`STATS_CACHE_TTL`]. Building it holds the global
/// `CLIENTS` lock (which every connection setup and teardown needs) for time proportional to the
/// number of clients and streams, so unauthenticated requests mustn't trigger it every time.
pub async fn generate_stats() -> anyhow::Result<String> {
	let mut cache = STATS_CACHE.lock().await;
	if let Some((at, stats)) = &*cache {
		if at.elapsed() < STATS_CACHE_TTL {
			return Ok(stats.clone());
		}
	}
	let stats = generate_stats_uncached().await?;
	*cache = Some((Instant::now(), stats.clone()));
	Ok(stats)
}

async fn generate_stats_uncached() -> anyhow::Result<String> {
	use tikv_jemalloc_ctl::stats::{active, allocated, mapped, metadata, resident, retained};
	tikv_jemalloc_ctl::epoch::advance()?;

	let memory = MemoryStats {
		active: active::read()?,
		allocated: allocated::read()?,
		mapped: mapped::read()?,
		metadata: metadata::read()?,
		resident: resident::read()?,
		retained: retained::read()?,
	};

	let clients_locked = CLIENTS.lock().await;
	let client_count = clients_locked.len();

	let mut clients = HashMap::with_capacity(clients_locked.len());
	for client in clients_locked
		.iter()
		.filter(|_| !CONFIG.server.stats_hide_clients)
	{
		clients.insert(
			client.0.to_string(),
			ClientStats {
				client_type: client.1 .1.clone(),
				streams: client
					.1
					 .0
					.lock()
					.await
					.iter()
					.map(|x| (x.0.to_string(), StreamStats::from(x.1.clone())))
					.collect(),
			},
		);
	}

	drop(clients_locked);

	let stats = ServerStats {
		config: CONFIG.ser()?,
		client_count,
		clients: (!CONFIG.server.stats_hide_clients).then_some(clients),
		memory,
	};

	Ok(serde_json::to_string_pretty(&stats)?)
}
