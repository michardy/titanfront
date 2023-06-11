use std::net::{SocketAddr, ToSocketAddrs};

/// App
// Modification of this object is not persisted
#[derive(Debug)]
pub struct AppConfig {
	/// Server encryption key
	pub key: Vec<u8>,
	/// UDP interface and port Titanfront should expose
	pub udp_address: SocketAddr,
	/// HTTP interface and port Titanfront should expose
	pub auth_address: SocketAddr,
	/// Address for binding relays.
	/// Port number should be 0
	pub relay_address: String,
	/// Number of permitted players excluding admins
	pub player_count: usize,
	/// Size of the TCP buffer
	pub receive_buf_size: usize,
	/// Array of admin usernames
	pub admins: Vec<u64>,
	/// List of servers addresses to proxy to
	pub target_servers: Vec<SocketAddr>,
	/// Which server should new players spawn in
	pub join_target: usize,
	/// Whether to use central authentication
	pub auth_enabled: bool,
	/// URL of the central auth server
	pub auth_server: String,
	pub name: String,
	pub description: String,
	pub password: String,
	// TODO: derive this rather than setting it
	pub version: String,
	pub modinfo: String,
}

impl AppConfig {
	pub fn new() -> AppConfig {
		let mut conf = config::Config::default();

		log::info!("Setting defaults");
		conf.set_default("udp_address", "0.0.0.0:37015").unwrap();

		conf.set_default("auth_address", "0.0.0.0:8081").unwrap();

		conf.set_default("relay_address", "0.0.0.0:0").unwrap();

		conf.set_default("player_count", 16).unwrap();

		conf.set_default("receive_buf_size", 2048).unwrap();

		conf.set_default("join_target", 0).unwrap();

		conf.set_default("auth_enabled", true).unwrap();

		conf.set_default("auth_server", "https://northstar.tf")
			.unwrap();

		conf.set_default("name", "Titanfront server").unwrap();

		conf.set_default("description", "Titanfront server")
			.unwrap();

		conf.set_default("password", "").unwrap();

		conf.set_default("version", "").unwrap();

		conf
			.set_default(
				"modinfo",
				r#"{"Mods":[{"Name":"Northstar.Custom","Version":"1.11.0","RequiredOnClient":true,"Pdiff":"// this is just an empty pdiff file so that if people roll back an update the pdiff file will be overwritten\n"}]}"#
			)
			.unwrap();

		log::info!("Merging configuration");
		conf.merge(config::File::with_name("Titanfront"))
			.unwrap()
			.merge(config::Environment::with_prefix("Titanfront"))
			.unwrap();

		log::info!("Building configuration struct");
		let mut admins: Vec<u64> = Vec::new();
		if let Ok(ads) = conf.get_array("admins") {
			for ad in ads {
				if let Ok(s) = ad.into_str() {
					match s.parse::<u64>() {
						Ok(u) => admins.push(u),
						Err(_) => panic!("Bad admin ID number"),
					}
				}
			}
		}

		let mut servers: Vec<SocketAddr> = Vec::new();
		if let Ok(servs) = conf.get_array("target_servers") {
			for serv in servs {
				if let Ok(s) = serv.into_str() {
					match s.parse() {
						Ok(addr) => servers.push(addr),
						Err(_) => match s.to_socket_addrs() {
							Ok(mut itr) => servers.push(itr.next().unwrap()),
							Err(_) => panic!("Bad target address"),
						},
					}
				}
			}
		}
		if servers.is_empty() {
			panic!("No target servers to proxy")
		}

		AppConfig {
			key: match conf.get_str("key") {
				Ok(ks) => base64::decode(ks).expect("Bad server key"),
				Err(_) => panic!("Did not specify server encryption key"),
			},
			udp_address: match conf.get_str("udp_address") {
				Ok(saddr) => match saddr.parse() {
					Ok(addr) => addr,
					Err(_) => panic!("Bad udp address"),
				},
				Err(_) => panic!("Bad udp address"),
			},
			auth_address: match conf.get_str("auth_address") {
				Ok(saddr) => match saddr.parse() {
					Ok(addr) => addr,
					Err(_) => panic!("Bad auth address"),
				},
				Err(_) => panic!("Bad auth address"),
			},
			relay_address: match conf.get_str("relay_address") {
				Ok(saddr) => saddr,
				Err(_) => panic!("Bad relay address"),
			},
			player_count: match conf.get_int("player_count") {
				Ok(p) => p as usize,
				Err(_) => panic!("Player number is not an int"),
			},
			receive_buf_size: match conf.get_int("receive_buf_size") {
				Ok(s) => s as usize,
				Err(_) => panic!("Buffer size is not an int"),
			},
			admins,
			target_servers: servers,
			join_target: match conf.get_int("join_target") {
				Ok(t) => t as usize,
				Err(_) => panic!("Join target is not an int"),
			},
			auth_enabled: match conf.get_bool("auth_enabled") {
				Ok(b) => b,
				Err(_) => panic!("Auth enabled is not a boolean value"),
			},
			auth_server: match conf.get_str("auth_server") {
				Ok(s) => s,
				Err(_) => panic!("Auth server is not a string"),
			},
			name: match conf.get_str("name") {
				Ok(s) => s,
				Err(_) => panic!("Name is not a string"),
			},
			description: match conf.get_str("description") {
				Ok(s) => s,
				Err(_) => panic!("Description is not a string"),
			},
			password: match conf.get_str("password") {
				Ok(s) => s,
				Err(_) => panic!("Password is not a string"),
			},
			version: match conf.get_str("version") {
				Ok(s) => s,
				Err(_) => panic!("Version is not a string"),
			},
			modinfo: match conf.get_str("modinfo") {
				Ok(s) => s,
				Err(_) => panic!("Modinfo is not a string"),
			},
		}
	}
}
