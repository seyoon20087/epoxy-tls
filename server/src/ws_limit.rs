//! WebSocket transport that limits how fast a client may send ping frames.
//!
//! tokio-websockets answers every ping by queueing a pong, and that queue is unbounded. A client
//! that never reads but keeps sending pings makes the server buffer pongs forever (before any
//! Wisp authentication happens). Browsers can't send pings and well-behaved clients send them
//! rarely, so anything above a small rate is treated as abuse and the connection is dropped.

use std::{
	fmt,
	pin::Pin,
	task::{Context, Poll},
	time::{Duration, Instant},
};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::{Message, WebSocketStream};
use wisp_mux::{ws::Payload, WispError};

/// Max pings accepted per window before the connection is closed.
const MAX_PINGS_PER_WINDOW: u32 = 32;
const PING_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct PingFlood;

impl fmt::Display for PingFlood {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("client exceeded ping rate limit")
	}
}
impl std::error::Error for PingFlood {}

pub struct PingLimiter {
	window_start: Instant,
	count: u32,
}

impl Default for PingLimiter {
	fn default() -> Self {
		Self {
			window_start: Instant::now(),
			count: 0,
		}
	}
}

impl PingLimiter {
	/// Record a ping. Returns false if the client is over the limit.
	pub fn record(&mut self) -> bool {
		let now = Instant::now();
		if now.duration_since(self.window_start) >= PING_WINDOW {
			self.window_start = now;
			self.count = 0;
		}
		self.count = self.count.saturating_add(1);
		self.count <= MAX_PINGS_PER_WINDOW
	}
}

fn map_err(x: tokio_websockets::Error) -> WispError {
	if matches!(x, tokio_websockets::Error::AlreadyClosed) {
		WispError::WsImplSocketClosed
	} else {
		WispError::WsImplError(Box::new(x))
	}
}

/// Server-side replacement for `wisp_mux::ws::TokioWebsocketsTransport` with ping limiting.
pub struct LimitedWsTransport<S: AsyncRead + AsyncWrite + Unpin> {
	ws: WebSocketStream<S>,
	pings: PingLimiter,
	flooded: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> LimitedWsTransport<S> {
	pub fn new(ws: WebSocketStream<S>) -> Self {
		Self {
			ws,
			pings: PingLimiter::default(),
			flooded: false,
		}
	}
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for LimitedWsTransport<S> {
	type Item = Result<Payload, WispError>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.flooded {
			return Poll::Ready(None);
		}
		loop {
			match self.ws.poll_next_unpin(cx) {
				Poll::Ready(Some(Ok(x))) => {
					if x.is_binary() {
						return Poll::Ready(Some(Ok(x.into_payload().into())));
					} else if x.is_close() {
						return Poll::Ready(None);
					} else if x.is_ping() && !self.pings.record() {
						self.flooded = true;
						return Poll::Ready(Some(Err(WispError::WsImplError(Box::new(
							PingFlood,
						)))));
					}
				}
				Poll::Ready(Some(Err(x))) => return Poll::Ready(Some(Err(map_err(x)))),
				Poll::Ready(None) => return Poll::Ready(None),
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Payload> for LimitedWsTransport<S> {
	type Error = WispError;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_ready_unpin(cx).map_err(map_err)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Payload) -> Result<(), Self::Error> {
		self.ws
			.start_send_unpin(Message::binary(item))
			.map_err(map_err)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_flush_unpin(cx).map_err(map_err)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_close_unpin(cx).map_err(map_err)
	}
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Message> for LimitedWsTransport<S> {
	type Error = tokio_websockets::Error;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_ready_unpin(cx)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
		self.ws.start_send_unpin(item)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_flush_unpin(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.ws.poll_close_unpin(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ping_limiter_allows_burst_then_trips() {
		let mut limiter = PingLimiter::default();
		for _ in 0..MAX_PINGS_PER_WINDOW {
			assert!(limiter.record());
		}
		assert!(!limiter.record());
	}

	#[test]
	fn ping_limiter_resets_after_window() {
		let mut limiter = PingLimiter::default();
		for _ in 0..=MAX_PINGS_PER_WINDOW {
			limiter.record();
		}
		limiter.window_start -= PING_WINDOW;
		assert!(limiter.record());
	}
}
