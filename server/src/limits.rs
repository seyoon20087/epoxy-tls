//! Caps on how many upstream streams clients can hold open, so one client (or many) can't
//! exhaust the server's file descriptors.

use std::sync::Arc;

use lazy_static::lazy_static;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::CONFIG;

lazy_static! {
	static ref OUTBOUND: Option<Arc<Semaphore>> = match CONFIG.stream.max_outbound_connections {
		0 => None,
		n => Some(Arc::new(Semaphore::new(n))),
	};
}

/// Per-client stream limiter, from `stream.max_streams_per_client`.
pub fn new_client_limit() -> Option<Arc<Semaphore>> {
	match CONFIG.stream.max_streams_per_client {
		0 => None,
		n => Some(Arc::new(Semaphore::new(n))),
	}
}

/// Held for a stream's lifetime; releases its slots when dropped.
pub struct StreamPermits {
	_client: Option<OwnedSemaphorePermit>,
	_global: Option<OwnedSemaphorePermit>,
}

/// Take a slot from the client's limit (if any) and the global limit. `None` if either is full.
pub fn try_acquire(client: Option<&Arc<Semaphore>>) -> Option<StreamPermits> {
	let client = match client {
		Some(x) => Some(x.clone().try_acquire_owned().ok()?),
		None => None,
	};
	let global = match &*OUTBOUND {
		Some(x) => Some(x.clone().try_acquire_owned().ok()?),
		None => None,
	};
	Some(StreamPermits {
		_client: client,
		_global: global,
	})
}
