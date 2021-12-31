use std::{
	sync::{Arc, RwLock},
	net::{
		SocketAddr,
		UdpSocket
	}
};

use dashmap::DashMap;

#[derive(Clone)]
pub struct AuthTables {
	/// Map of auth tokens. 
	tokens: Arc<DashMap<String, SocketAddr>>,
	/// Map of client addresses to relay sockets
	ips: Arc<DashMap<SocketAddr, UdpSocket>>,
	// Dashmap is not really benchmarked for an update workload
	// Others are fine but this may be slow
	/// Socket use timestamps
	/// Used to disconnect dead sessions
	counters: Arc<DashMap<SocketAddr,u64>>,
	// TODO: consider making non blocking
	/// Available relay sockets
	available: Arc<RwLock<Vec<UdpSocket>>>
}


pub type Request = tide::Request<AuthTables>;

fn relay_incoming(auth_tables: &AuthTables) {

}

#[async_std::main]
async fn main() -> tide::Result<()> {
	// Setup UDP relaying sockets
	let proxy_sock = UdpSocket::bind("0.0.0.0:37015").expect("Configured proxy address could not be bound");
	let mut internal_sockets: Vec<UdpSocket> = Vec::with_capacity(16);
	for _ in 0..16 {
		internal_sockets.push(UdpSocket::bind("0.0.0.0:0").expect("Cannot allocate socket for client relay"));
	}

	let auth_tables = AuthTables {
		tokens: Arc::new(DashMap::new()),
		ips: Arc::new(DashMap::new()),
		counters: Arc::new(DashMap::new()),
		available: Arc::new(RwLock::new(internal_sockets))
	};

	// Setup authserver
	let mut authserver = tide::with_state(auth_tables);
	authserver.listen("0.0.0.0:8081").await?;
	Ok(())
}
