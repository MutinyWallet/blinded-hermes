use axum::http::StatusCode;
use axum::Json;
use nostr::PublicKey;
use serde_json::{json, Value};
use std::{collections::HashMap, str::FromStr};

use crate::State;

pub fn well_known_nip5(
    state: &State,
    name: String,
) -> Result<HashMap<String, PublicKey>, (StatusCode, Json<Value>)> {
    let user = state.db.get_user_by_name(name).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "ERROR", "error": e.to_string()})),
        )
    })?;

    let mut names = HashMap::new();
    if let Some(user) = user {
        names.insert(
            user.name,
            PublicKey::from_str(&user.pubkey).expect("valid npub"),
        );
    } else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"status": "ERROR", "error": "Not Found"})),
        ));
    }

    Ok(names)
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests_integration {
    use nostr::Keys;
    use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
    use std::{str::FromStr, sync::Arc};

    use crate::{
        db::setup_db, mint::MockMultiMintWrapperTrait, models::app_user::NewAppUser,
        nostr::well_known_nip5, register::BlindSigner, State,
    };

    #[tokio::test]
    pub async fn well_known_nip5_lookup_test() {
        dotenv::dotenv().ok();
        let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = setup_db(pg_url);

        // swap out fm with a mock here since that's not what is being tested
        let mock_mm = MockMultiMintWrapperTrait::new();

        // nostr
        let nostr_nsec_str = std::env::var("NSEC").expect("FM_DB_PATH must be set");
        let nostr_sk = Keys::parse(nostr_nsec_str).expect("Invalid NOSTR_SK");
        let nostr = nostr_sdk::Client::new(&nostr_sk);

        // create blind signer
        let free_signer = BlindSigner::derive(&[0u8; 32], 0, 0);
        let paid_signer = BlindSigner::derive(&[0u8; 32], 0, 0);

        let mock_mm = Arc::new(mock_mm);
        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            free_pk: free_signer.pk,
            paid_pk: paid_signer.pk,
            domain: "http://127.0.0.1:8080".to_string(),
            nostr_sk,
        };

        let username = "wellknownuser".to_string();
        let kpk1 = PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();
        let pk1 = XOnlyPublicKey::from(kpk1);
        let user = NewAppUser {
            pubkey: "e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443".to_string(),
            name: username.clone(),
            federation_id: "".to_string(),
            unblinded_msg: "".to_string(),
            federation_invite_code: "".to_string(),
        };

        // don't care about error if already exists
        let _ = state.db.insert_new_user(user);

        match well_known_nip5(&state, username.clone()) {
            Ok(result) => {
                assert_eq!(result.get(&username).unwrap().to_string(), pk1.to_string());
            }
            Err((_code, json)) => panic!("shouldn't error: {json:?}"),
        }
    }
}
