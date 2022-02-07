use std::{net::{UdpSocket, ToSocketAddrs, SocketAddr}, hash::Hash, io};

/// Hashable UDP socket
pub struct TUdpSocket {
	sock: UdpSocket,
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

pub trait TryClone<T> {
	fn try_clone(&self) -> io::Result<T>;
}

impl TryClone<TUdpSocket> for TUdpSocket {
	fn try_clone(&self) -> io::Result<Self> {
		Ok(TUdpSocket {
			sock: self.sock.try_clone()?,
			id: self.id
		})
	}
}

impl TryClone<Vec<TUdpSocket>> for Vec<TUdpSocket> {
	fn try_clone(&self) -> io::Result<Self> {
		let mut out: Vec<TUdpSocket> = Vec::with_capacity(self.len());
		for s in self {
			out.push(s.try_clone()?)
		}
		Ok(out)
	}
}

impl TUdpSocket {
	pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
		self.sock.send_to(buf, addr)
	}
	pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
		self.sock.recv_from(buf)
	}
	pub fn bind<A: ToSocketAddrs>(addr: A, id: usize) -> io::Result<TUdpSocket> {
		Ok(TUdpSocket {
			sock: UdpSocket::bind(addr)?,
			id: id
		})
	}
}