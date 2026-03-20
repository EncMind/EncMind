use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::routes::PeerAddr;
use crate::tls::TlsLifecycleManager;

/// Listener that accepts TCP sockets and performs a Rustls server handshake
/// before yielding the stream to axum/hyper.
pub struct TlsTcpListener {
    tcp: TcpListener,
    tls_manager: Arc<TlsLifecycleManager>,
    handshake_timeout: Duration,
}

impl TlsTcpListener {
    pub fn new(tcp: TcpListener, tls_manager: Arc<TlsLifecycleManager>) -> Self {
        Self {
            tcp,
            tls_manager,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl Listener for TlsTcpListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp_stream, addr) = match self.tcp.accept().await {
                Ok(tup) => tup,
                Err(err) => {
                    handle_accept_error(err).await;
                    continue;
                }
            };

            let acceptor = TlsAcceptor::from(self.tls_manager.server_config());
            let handshake = acceptor.accept(tcp_stream);
            match tokio::time::timeout(self.handshake_timeout, handshake).await {
                Ok(Ok(tls_stream)) => return (tls_stream, addr),
                Ok(Err(err)) => {
                    warn!(%addr, error = %err, "tls handshake failed");
                }
                Err(_) => {
                    warn!(%addr, "tls handshake timed out");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

impl Connected<IncomingStream<'_, TlsTcpListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TlsTcpListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

async fn handle_accept_error(e: io::Error) {
    if is_connection_error(&e) {
        return;
    }

    warn!("tcp accept error: {e}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}
