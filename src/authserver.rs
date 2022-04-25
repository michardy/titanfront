use crate::{router::Router, appconfig::AppConfig};
use serde::Deserialize;
use tide::{Response, Request, Result};

#[derive(Clone)]
struct State {
	router: Router,
	conf: AppConfig
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

async fn verify(_req: Request<State>) -> Result {
	Ok(
		Response::builder(200)
			// This string is checked literally by the NorthstarMasterServer
			.body("I am a northstar server!")
			.header("X-Forwarded-By", "Titanfront")
			.build()
	)
}

async fn auth_incoming_player(req: Request<State>) -> Result {
	// TODO: check server auth token
	let con_req: ConnectRequest = req.query()?;
	let conf = &req.state().conf;
	match req.state().router.add_token(con_req.authToken, con_req.id, &conf) {
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

pub async fn build_and_run(router: Router, conf: AppConfig) -> Result<()> {
	// Setup authserver
	log::info!("Setting up auth server");
	let state = State{
		router: router,
		conf: conf.clone()
	};
	let mut authserver = tide::with_state(state);
	authserver.at("/verify").get(verify);
	authserver.at("/authenticate_incoming_player").post(auth_incoming_player);
	log::info!("Starting auth server");
	authserver.listen(conf.auth_address).await?;
	Ok(())
}