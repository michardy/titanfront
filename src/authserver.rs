use crate::{
	router::Router,
	appconfig::AppConfig,
	apperr::TitanfrontError,
	Err
};

use {
	async_macros::select,
	serde::{
		Deserialize,
		Serialize
	},
	surf::Url,
	tide::{
		Response,
		Request,
		Server},
	async_std::task,
	anyhow::Result
};

use std::{
	sync::{
		RwLock,
		Arc
	},
	time::Duration
};

#[derive(Clone)]
struct State {
	router: Router,
	conf: AppConfig,
	server_auth: Arc<RwLock<String>>,
	server_id: Arc<RwLock<String>>
}

#[derive(Deserialize)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct ConnectRequest {
	/// Player ID
	id: u64,
	/// Randomly generated 28 bit player auth token
	authToken: String,
	/// Token to authenticate NorthstarMasterServer instance
	serverAuthToken: String,
	username: String,
	password: Option<String>
}

#[derive(Serialize)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct AddRequest {
	port: u16,
	authPort: u16,
	name: String,
	description: String,
	map: String,
	playlist: String,
	maxPlayers: u64,
	password: String
}

#[derive(Deserialize)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct AddResponse {
	success: bool,
	id: Option<String>,
	serverAuthToken: Option<String>,
	// TODO: What is the type of error?
	// error: Option<any>
}

async fn verify(_req: Request<State>) -> tide::Result {
	Ok(
		Response::builder(200)
			// This string is checked literally by the NorthstarMasterServer
			.body("I am a northstar server!")
			.header("X-Forwarded-By", "Titanfront")
			.build()
	)
}

async fn auth_incoming_player(req: Request<State>) -> tide::Result {
	let state = req.state();
	let con_req: ConnectRequest = req.query()?;
	let conf = &state.conf;
	// You can't seem to compare an RwGuard<String> with a String using !=
	if state.server_auth.read().unwrap().ne(&con_req.serverAuthToken) {
		return Ok(
			Response::builder(403)
				.body("{\"success\":false}")
				.content_type("application/json")
				.header("X-Forwarded-By", "Titanfront")
				.build()
		);
	}
	match state.router.add_token(con_req.authToken, con_req.id, &conf) {
		Ok(_) => {
			Ok(
				Response::builder(200)
					.body("{\"success\":true}")
					.content_type("application/json")
					.header("X-Forwarded-By", "Titanfront")
					.build()
			)
		},
		Err(_) => {
			Ok(
				// Northstar appears to return 200s for failures
				// HTTP status codes do not cleanly map 503 seems closest
				Response::builder(503)
					.body("{\"success\":false}")
					.content_type("application/json")
					.header("X-Forwarded-By", "Titanfront")
					.build()
			)
		}
	}
}

async fn publish_server(state: &State) -> Result<()> {
	task::sleep(Duration::from_secs(1)).await;
	let mut url = Url::parse("http://127.0.0.1/verify").unwrap();
	let conf = &state.conf;
	match url.set_ip_host(conf.auth_address.ip()) {
		Ok(_) => {},
		Err(_) => log::warn!("Attempt to set IP for liveness check failed. Falling back")
	}
	match surf::get(url).recv_string().await {
		Ok(s) => {
			if s != "I am a northstar server!" {
				log::error!("Possible port contention");
				return Err!(TitanfrontError::AuthPortBindErr());
			}
		},
		Err(e) => {
			log::error!("Liveness check failed");
			return Err!(TitanfrontError::AuthLiveErr(e));
		}
	}
	let add_req = AddRequest {
		port: conf.udp_address.port(),
		authPort: conf.auth_address.port(),
		name: conf.name.clone(),
		description: conf.description.clone(),
		map: String::from("????"),
		playlist: String::from("????"),
		maxPlayers: conf.player_count as u64,
		password: conf.password.clone()
	};
	let post_req = surf::post(format!("{}/server/add_server", conf.auth_server))
		.body_json(&add_req).or_else(
			|err|{Err!(TitanfrontError::AddRequestErr(err))}
		)?
		.recv_json::<AddResponse>();
	match post_req.await {
		Ok(r) => {
			if r.success == true {
				let mut auth = state.server_auth.write().unwrap();
				*auth = r.serverAuthToken
					.ok_or_else(||{TitanfrontError::NMSNoAuthErr()})?
					.clone();
				let mut id = state.server_id.write().unwrap();
				*id = r.id
					.ok_or_else(||{TitanfrontError::NMSNoIDErr()})?
					.clone();
			}
		},
		Err(e) => {
			log::error!("NorthstarMasterServer issued bad response to registration");
			return Err!(TitanfrontError::NMSResponseErr(e));
		}
	}
	Ok(())
}
async fn server_caller(server: Server<State>, conf: AppConfig) -> Result<()> {
	server.listen(conf.auth_address).await.or_else(|err|{Err!(err)})
}


pub async fn build_and_run(router: Router, conf: AppConfig) -> Result<()> {
	// Setup authserver
	log::info!("Setting up auth server");
	let state = State{
		router: router,
		conf: conf.clone(),
		server_id: Arc::new(RwLock::new(String::new())),
		server_auth: Arc::new(RwLock::new(String::new()))
	};
	let mut authserver = tide::with_state(state.clone());
	authserver.at("/verify").get(verify);
	authserver.at("/authenticate_incoming_player").post(auth_incoming_player);

	let publish = publish_server(&state);

	log::info!("Starting auth server");
	let serv = server_caller(authserver, conf);

	select!(publish, serv).await
}