use std::str::FromStr;

use crate::{
    routes::{RegisterRequest, RegisterResponse},
    State,
};
use fedimint_core::api::InviteCode;
use lazy_regex::*;
use log::error;
use reqwest::StatusCode;

pub static ALPHANUMERIC_REGEX: Lazy<Regex> = lazy_regex!("^[a-zA-Z0-9]+$");

pub fn is_valid_name(name: &str) -> bool {
    let name_len = name.len();
    if !(2..=30).contains(&name_len) {
        return false;
    }

    ALPHANUMERIC_REGEX.is_match(name)
}

pub fn check_available(state: &State, name: String) -> anyhow::Result<bool> {
    if !is_valid_name(&name) {
        return Ok(false);
    }

    state.db.check_name_available(name)
}

pub async fn register(
    state: &State,
    req: RegisterRequest,
) -> Result<RegisterResponse, (StatusCode, String)> {
    if !is_valid_name(&req.name) {
        return Err((StatusCode::BAD_REQUEST, "Unavailable".to_string()));
    }

    if !req.verify(state.auth_pk) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid blind sig".to_string()));
    }
    // todo save nonce to db and check for replay attacks

    match state.db.check_name_available(req.name.clone()) {
        Ok(true) => (),
        Ok(false) => {
            return Err((StatusCode::BAD_REQUEST, "Unavailable".to_string()));
        }
        Err(e) => {
            error!("Error in register: {e:?}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "ServerError".to_string()));
        }
    };

    // make sure the federation is either already added or connectable
    if !state.mm.check_has_federation(req.federation_id).await {
        let invite_code = match InviteCode::from_str(&req.federation_invite_code) {
            Ok(i) => i,
            Err(e) => {
                error!("Error in register: {e:?}");
                return Err((StatusCode::BAD_REQUEST, "InvalidFederation".to_string()));
            }
        };

        match state.mm.register_new_federation(invite_code).await {
            Ok(_) => (),
            Err(e) => {
                error!("Error in register: {e:?}");
                return Err((StatusCode::BAD_REQUEST, "InvalidFederation".to_string()));
            }
        }
    }

    // TODO insert blinding info and new user as an atomic transaction

    match state.db.insert_new_user(req.into()) {
        Ok(_) => Ok(RegisterResponse {}),
        Err(e) => {
            error!("Errorgister: {e:?}");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "ServerError".to_string()))
        }
    }
}

#[cfg(all(test, not(feature = "integration-tests")))]
mod tests {
    use crate::register::is_valid_name;

    #[tokio::test]
    async fn check_name() {
        // bad names
        assert!(!is_valid_name("thisisoverthe30characternamelimit"));
        assert!(!is_valid_name("thisisoverthe30characternamelimit"));
        assert!(!is_valid_name("no!"));
        assert!(!is_valid_name("n"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("bad&name"));
        assert!(!is_valid_name("bad space name"));
        assert!(!is_valid_name("bad_name"));

        // good
        assert!(is_valid_name("goodname"));
        assert!(is_valid_name("goodname1"));
        assert!(is_valid_name("yesnameisverygoodandunderlimit"));
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests_integration {
    use std::{str::FromStr, sync::Arc};

    use fedimint_core::{api::InviteCode, config::FederationId, PeerId};
    use nostr::{key::FromSkStr, Keys};
    use secp256k1::Secp256k1;

    use crate::{
        db::setup_db,
        mint::MockMultiMintWrapperTrait,
        models::app_user::NewAppUser,
        register::{check_available, register},
        routes::RegisterRequest,
        State,
    };

    #[tokio::test]
    pub async fn test_username_checker() {
        dotenv::dotenv().ok();
        let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = setup_db(pg_url);

        // swap out fm with a mock here since that's not what is being tested
        let mock_mm = Arc::new(MockMultiMintWrapperTrait::new());

        let nostr_nsec_str = std::env::var("NSEC").expect("FM_DB_PATH must be set");
        let nostr_sk = Keys::from_sk_str(&nostr_nsec_str).expect("Invalid NOSTR_SK");
        let nostr = nostr_sdk::Client::new(&nostr_sk);

        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            domain: "http://127.0.0.1:8080".to_string(),
        };

        let name = "veryuniquename123".to_string();
        let available = check_available(&state, name).expect("should get");
        assert!(available);

        let commonname = "commonname".to_string();
        let common_app_user = NewAppUser {
            pubkey: "".to_string(),
            name: commonname.clone(),
            federation_id: "".to_string(),
            federation_invite_code: "".to_string(),
        };

        // don't care about error if already exists
        let _ = state.db.insert_new_user(common_app_user);

        let available = check_available(&state, commonname).expect("should get");
        assert!(!available);
    }

    #[tokio::test]
    pub async fn register_username_tests() {
        dotenv::dotenv().ok();
        let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = setup_db(pg_url);

        // swap out fm with a mock here since that's not what is being tested
        let mut mock_mm = MockMultiMintWrapperTrait::new();
        mock_mm
            .expect_check_has_federation()
            .times(1)
            .returning(|_| true);

        // nostr
        let nostr_nsec_str = std::env::var("NSEC").expect("FM_DB_PATH must be set");
        let nostr_sk = Keys::from_sk_str(&nostr_nsec_str).expect("Invalid NOSTR_SK");
        let nostr = nostr_sdk::Client::new(&nostr_sk);

        let mock_mm = Arc::new(mock_mm);
        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            domain: "http://127.0.0.1:8080".to_string(),
        };

        let connect = InviteCode::new(
            "ws://test1".parse().unwrap(),
            PeerId::from_str("1").unwrap(),
            FederationId::dummy(),
        );
        let req = RegisterRequest {
            name: "registername".to_string(),
            pubkey: "".to_string(),
            federation_id: connect.federation_id(),
            federation_invite_code: connect.to_string(),
        };

        match register(&state, req).await {
            Ok(_) => (),
            Err(_) => {
                panic!("shouldn't error")
            }
        }
    }

    #[tokio::test]
    pub async fn register_username_add_unknown_federation_tests() {
        dotenv::dotenv().ok();
        let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = setup_db(pg_url);

        // swap out fm with a mock here since that's not what is being tested
        let mut mock_mm = MockMultiMintWrapperTrait::new();
        mock_mm
            .expect_check_has_federation()
            .times(1)
            .returning(|_| false);

        mock_mm
            .expect_register_new_federation()
            .times(1)
            .returning(|_| Ok(()));

        // nostr
        let nostr_nsec_str = std::env::var("NSEC").expect("FM_DB_PATH must be set");
        let nostr_sk = Keys::from_sk_str(&nostr_nsec_str).expect("Invalid NOSTR_SK");
        let nostr = nostr_sdk::Client::new(&nostr_sk);

        let mock_mm = Arc::new(mock_mm);
        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            domain: "http://127.0.0.1:8080".to_string(),
        };

        let connect = InviteCode::new(
            "ws://test1".parse().unwrap(),
            PeerId::from_str("1").unwrap(),
            FederationId::dummy(),
        );
        let req = RegisterRequest {
            name: "newfederationusername".to_string(),
            pubkey: "".to_string(),
            federation_id: connect.federation_id(),
            federation_invite_code: connect.to_string(),
        };

        match register(&state, req).await {
            Ok(_) => (),
            Err(_) => {
                panic!("shouldn't error")
            }
        }
    }
}
