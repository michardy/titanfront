mod appconfig;
mod apperr;
mod authserver;
mod router;
mod tsock;

use crate::{
	router::{external_handler, internal_handler, Router},
	tsock::TUdpSocket,
};

use std::{panic, process, sync::Arc};

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
	env_logger::init();

	log::info!("Parsing config");
	let conf = appconfig::AppConfig::new();

	log::info!("Create UDP sockets");
	// Setup UDP relaying sockets
	let proxy_sock = TUdpSocket::bind(conf.udp_address, usize::MAX).await?;
	let mut internal_sockets: Vec<TUdpSocket> = Vec::with_capacity(16);
	log::info!("Binding UDP sockets");
	for i in 0..conf.player_count + conf.admins.len() {
		internal_sockets.push(
			TUdpSocket::bind(&conf.relay_address, i)
				.await
				.expect("Failed to create internal socket"),
		);
	}

	log::info!("Create route tables");
	let auth_tables = Arc::new(Router::new(&internal_sockets));

	let orig_hook = panic::take_hook();
	panic::set_hook(Box::new(move |panic_info| {
		// invoke the default handler and exit the process
		orig_hook(panic_info);
		process::exit(1);
	}));

	let conf_pointer = Arc::new(conf);

	log::info!("Spawn server receive threads");
	for s in internal_sockets {
		let cfg = conf_pointer.clone();
		let prxy = proxy_sock.clone();
		let tables = auth_tables.clone();
		tokio::spawn(async move {
			internal_handler(s, cfg, tables, prxy).await
                // Thread errors cannot propagate back to the main thread
                // If they are unhandled by now they are fatal errors
                .unwrap();
		});
	}

	log::info!("Spawn player receive threads");
	let cfg = conf_pointer.clone();
	let prxy = proxy_sock.clone();
	let tables = auth_tables.clone();
	tokio::spawn(async move {
		external_handler(prxy, cfg, tables).await
			// Thread errors cannot propagate back to the main thread
			// If they are unhandled by now they are fatal errors
			.unwrap();
	});

	authserver::build_and_run(auth_tables, conf_pointer.clone()).await
}
