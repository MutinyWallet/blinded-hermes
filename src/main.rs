use axum::headers::Origin;
use axum::http::{Method, StatusCode, Uri};
use axum::routing::get;
use axum::{extract::DefaultBodyLimit, routing::post};
use axum::{http, Extension, Router, TypedHeader};
use log::{error, info};
use nostr_sdk::nostr::{key::FromSkStr, Keys};
use secp256k1::{All, Secp256k1};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tbs::{AggregatePublicKey, PubKeyPoint};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    db::{setup_db, DBConnection},
    invoice::handle_pending_invoices,
    mint::{setup_multimint, MultiMintWrapperTrait},
    routes::{
        check_pubkey, check_username, health_check, lnurl_callback_route, lnurl_verify_route,
        register_route, root, validate_cors, well_known_lnurlp_route,
        well_known_nip5_route,
    },
};

mod db;
mod invoice;
mod lnurlp;
mod mint;
mod models;
mod nostr;
mod register;
mod routes;

const ALLOWED_ORIGINS: [&str; 6] = [
    "https://app.mutinywallet.com",
    "capacitor://localhost",
    "https://signet-app.mutinywallet.com",
    "http://localhost:3420",
    "http://localhost",
    "https://localhost",
];

const ALLOWED_SUBDOMAIN: &str = ".mutiny-web.pages.dev";
const ALLOWED_LOCALHOST: &str = "http://127.0.0.1:";

const API_VERSION: &str = "v1";

const RELAYS: [&str; 9] = [
    "wss://nostr.mutinywallet.com",
    "wss://relay.mutinywallet.com",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nostr.wine",
    "wss://nostr.zbd.gg",
    "wss://relay.nos.social",
];

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SignerIdentity {
    pub service_id: i32,
    pub plan_id: i32,
}

#[derive(Clone)]
pub struct State {
    db: Arc<dyn DBConnection + Send + Sync>,
    mm: Arc<dyn MultiMintWrapperTrait + Send + Sync>,
    pub secp: Secp256k1<All>,
    pub nostr: nostr_sdk::Client,
    pub domain: String,
    pub free_pk: AggregatePublicKey,
    pub paid_pk: AggregatePublicKey,
}

impl State {
    pub fn domain_no_http(&self) -> String {
        self.domain
            .replace("http://", "")
            .replace("https://", "")
            .replace('/', "")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenv::dotenv().ok();
    pretty_env_logger::try_init()?;

    // get values key from env
    let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let port: u16 = std::env::var("VSS_PORT")
        .ok()
        .map(|p| p.parse::<u16>())
        .transpose()?
        .unwrap_or(8080);

    // fedimint
    let fm_db_path = std::env::var("FM_DB_PATH").expect("FM_DB_PATH must be set");
    let fm_db_path = PathBuf::from_str(&fm_db_path).expect("Invalid fm db path");
    let mm = setup_multimint(fm_db_path)
        .await
        .expect("should set up mints");

    let free_pk = std::env::var("FREE_PK").expect("FREE_PK must be set");
    let paid_pk = std::env::var("PAID_PK").expect("PAID_PK must be set");
    let free_pk: AggregatePublicKey = AggregatePublicKey(
        PubKeyPoint::from_compressed(
            hex::decode(&free_pk).expect("Invalid key hex")[..]
                .try_into()
                .expect("Invalid key byte key"),
        )
        .expect("Invalid FREE_PK"),
    );
    let paid_pk: AggregatePublicKey = AggregatePublicKey(
        PubKeyPoint::from_compressed(
            hex::decode(&paid_pk).expect("Invalid key hex")[..]
                .try_into()
                .expect("Invalid key byte key"),
        )
        .expect("Invalid PAID_PK"),
    );

    // nostr
    let nostr_nsec_str = std::env::var("NSEC").expect("NSEC must be set");
    let nostr_sk = Keys::from_sk_str(&nostr_nsec_str).expect("Invalid NOSTR_SK");
    let nostr = nostr_sdk::Client::new(&nostr_sk);
    nostr.add_relays(RELAYS).await.expect("Failed to add relays");
    nostr.connect().await;

    // domain
    let domain = std::env::var("DOMAIN_URL")
        .expect("DOMAIN_URL must be set")
        .to_string();

    let db = setup_db(pg_url);
    let secp = Secp256k1::new();
    let state = State {
        db,
        mm,
        secp,
        nostr,
        domain,
        free_pk,
        paid_pk,
    };

    // spawn a task to check for previous pending invoices
    let cloned_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_pending_invoices(&cloned_state).await {
            error!("Error handling pending invoices: {e}")
        }
    });

    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .expect("Failed to parse bind/port for webserver");

    let server_router = Router::new()
        .route("/", get(root))
        .route("/health-check", get(health_check))
        .route("/v1/check-username/:username", get(check_username))
        .route("/v1/check-pubkey/:pubkey", get(check_pubkey))
        .route("/v1/register", post(register_route))
        .route("/.well-known/nostr.json", get(well_known_nip5_route))
        .route(
            "/.well-known/lnurlp/:username",
            get(well_known_lnurlp_route),
        )
        .route("/lnurlp/:username/callback", get(lnurl_callback_route))
        .route("/lnurlp/:username/verify/:op_id", get(lnurl_verify_route))
        .fallback(fallback)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                ]),
        )
        .layer(DefaultBodyLimit::max(10_000_000)) // max 10mb body size
        .layer(Extension(state));

    // Set up a oneshot channel to handle shutdown signal
    let (tx, rx) = oneshot::channel();

    // Spawn a task to listen for shutdown signals
    tokio::spawn(async move {
        let mut term_signal = signal(SignalKind::terminate())
            .map_err(|e| error!("failed to install TERM signal handler: {e}"))
            .unwrap();
        let mut int_signal = signal(SignalKind::interrupt())
            .map_err(|e| {
                error!("failed to install INT signal handler: {e}");
            })
            .unwrap();

        tokio::select! {
            _ = term_signal.recv() => {
                info!("Received SIGTERM");
            },
            _ = int_signal.recv() => {
                info!("Received SIGINT");
            },
        }

        let _ = tx.send(());
    });

    let server = axum::Server::bind(&addr).serve(server_router.into_make_service());

    info!("Webserver running on http://{addr}");

    let graceful = server.with_graceful_shutdown(async {
        let _ = rx.await;
    });

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        error!("shutdown error: {e}");
    }

    info!("Graceful shutdown complete");

    Ok(())
}

async fn fallback(origin: Option<TypedHeader<Origin>>, uri: Uri) -> (StatusCode, String) {
    if let Err((status, msg)) = validate_cors(origin) {
        return (status, msg);
    };

    (StatusCode::NOT_FOUND, format!("No route for {uri}"))
}
