use std::{hash::Hash, io, net::SocketAddr, sync::Arc};

use tokio::net::{ToSocketAddrs, UdpSocket};

#[derive(Debug, Clone)]
/// Hashable UDP socket
pub struct TUdpSocket {
	sock: Arc<UdpSocket>,
	id: usize,
}

impl Hash for TUdpSocket {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.id.hash(state);
	}
}

impl PartialEq for TUdpSocket {
	fn eq(&self, other: &Self) -> bool {
		self.id == other.id
	}
}

impl Eq for TUdpSocket {}

impl TUdpSocket {
	pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
		self.sock.send_to(buf, addr).await
	}
	pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
		self.sock.recv_from(buf).await
	}
	pub async fn bind<A: ToSocketAddrs>(addr: A, id: usize) -> io::Result<TUdpSocket> {
		Ok(TUdpSocket {
			sock: Arc::new(UdpSocket::bind(addr).await?),
			id,
		})
	}
}
