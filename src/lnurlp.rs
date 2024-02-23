use crate::State;
use anyhow::anyhow;
use fedimint_core::Amount;

use crate::routes::{LnurlStatus, LnurlType, LnurlWellKnownResponse};

pub async fn well_known_lnurlp(
    state: &State,
    name: String,
) -> anyhow::Result<LnurlWellKnownResponse> {
    let user = state.db.get_user_by_name(name.clone())?;
    if user.is_none() {
        return Err(anyhow!("NotFound"));
    }

    let res = LnurlWellKnownResponse {
        callback: format!("{}/lnurlp/{}/callback", state.domain, name).parse()?,
        max_sendable: Amount { msats: 100000 },
        min_sendable: Amount { msats: 1000 },
        metadata: "test metadata".to_string(), // TODO what should this be?
        comment_allowed: None,
        tag: LnurlType::PayRequest,
        status: LnurlStatus::Ok,
        nostr_pubkey: Some(state.nostr.keys().await.public_key()),
        allows_nostr: true,
    };

    Ok(res)
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests_integration {
    use nostr::{key::FromSkStr, Keys};
    use secp256k1::Secp256k1;
    use std::sync::Arc;

    use crate::{
        db::setup_db, lnurlp::well_known_lnurlp, mint::MockMultiMintWrapperTrait,
        models::app_user::NewAppUser, State,
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
        let nostr_sk = Keys::from_sk_str(&nostr_nsec_str).expect("Invalid NOSTR_SK");
        let nostr = nostr_sdk::Client::new(&nostr_sk);

        let mock_mm = Arc::new(mock_mm);
        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            domain: "http://hello.com".to_string(),
        };

        let username = "wellknownuser".to_string();
        let user = NewAppUser {
            pubkey: "e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443".to_string(),
            name: username.clone(),
            federation_id: "".to_string(),
            federation_invite_code: "".to_string(),
        };

        // don't care about error if already exists
        let _ = state.db.insert_new_user(user);

        match well_known_lnurlp(&state, username.clone()).await {
            Ok(result) => {
                assert_eq!(
                    result.callback,
                    "http://hello.com/lnurlp/wellknownuser/callback"
                        .parse()
                        .unwrap()
                );
            }
            Err(e) => panic!("shouldn't error: {e}"),
        }
    }
}
