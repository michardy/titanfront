mod appconfig;
mod tsock;
mod authserver;
mod router;
mod apperr;

use crate::{
	tsock::TUdpSocket,
	router::{Router, monitor_internal_routing, monitor_external_routing},
};

use std::{
	net::{
		UdpSocket
	}
};

use {
	anyhow::Result,
	async_macros::select,
	futures::future
};

#[async_std::main]
async fn main() -> Result<()> {

	env_logger::init();

	log::info!("Parsing config");
	let conf = appconfig::AppConfig::new();

	log::info!("Create UDP sockets");
	// Setup UDP relaying sockets
	let proxy_sock = UdpSocket::bind(conf.udp_address)?;
	let mut internal_sockets: Vec<TUdpSocket> = Vec::with_capacity(16);
	log::info!("Binding UDP sockets");
	for i in 0..conf.player_count+conf.admins.len() {
		internal_sockets.push(
			TUdpSocket::bind(&conf.relay_address, i)
				.expect("Failed to create internal socket")
		);
	}

	log::info!("Create route tables");
	let auth_tables = Router::new(&internal_sockets);

	let mut internal_monitor_tasks: Vec<_> = Vec::new();
	log::info!("Spawn server receive threads");
	for s in internal_sockets {
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		internal_monitor_tasks.push(
			monitor_internal_routing(s, cfg, tables, prxy)
		);
	}

	// Internal and external futures are different types
	let mut external_monitor_tasks: Vec<_> = Vec::new();
	log::info!("Spawn player receive threads");
	for _ in 0..conf.player_count+conf.admins.len() {
		// Yes, clones are expensive but this is fixed startup cost
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		external_monitor_tasks.push(
				monitor_external_routing(prxy, cfg, tables)
		);
	}

	let mut server = authserver::build_and_run(auth_tables, conf);
	let sel_int = future::select_all(internal_monitor_tasks);
	let sel_ext = future::select_all(external_monitor_tasks);
	select!(server, sel_int, sel_ext).await
}
