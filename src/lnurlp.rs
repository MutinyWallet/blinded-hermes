use std::str::FromStr;

use crate::{
    invoice::{spawn_invoice_subscription, InvoiceState},
    models::{invoice::NewInvoice, zaps::NewZap},
    routes::{LnurlCallbackParams, LnurlCallbackResponse, LnurlVerifyResponse},
    State,
};
use anyhow::anyhow;
use fedimint_core::{config::FederationId, Amount};
use fedimint_ln_client::LightningClientModule;
use nostr::{Event, JsonUtil, Kind};

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

const MIN_AMOUNT: u64 = 1000;

pub async fn lnurl_callback(
    state: &State,
    name: String,
    params: LnurlCallbackParams,
) -> anyhow::Result<LnurlCallbackResponse> {
    let user = state.db.get_user_by_name(name.clone())?;
    if user.is_none() {
        return Err(anyhow!("NotFound"));
    }
    let user = user.expect("just checked");

    if params.amount < MIN_AMOUNT {
        return Err(anyhow::anyhow!("Amount < MIN_AMOUNT"));
    }

    // verify nostr param is a zap request
    if params
        .nostr
        .as_ref()
        .is_some_and(|n| Event::from_json(n).is_ok_and(|e| e.kind == Kind::ZapRequest))
    {
        return Err(anyhow::anyhow!("Invalid nostr event"));
    }

    let federation_id = FederationId::from_str(&user.federation_id)
        .map_err(|e| anyhow::anyhow!("Invalid federation_id: {e}"))?;

    let client = state
        .mm
        .get_federation_client(federation_id)
        .await
        .map_or(Err(anyhow!("NotFound")), Ok)?;

    let ln = client.get_first_module::<LightningClientModule>();

    let (op_id, pr) = ln
        .create_bolt11_invoice(
            Amount {
                msats: params.amount,
            },
            "test invoice".to_string(), // todo set description hash properly
            None,
            (),
        )
        .await?;

    // insert invoice into db for later verification
    let new_invoice = NewInvoice {
        federation_id: federation_id.to_string(),
        op_id: op_id.to_string(),
        app_user_id: user.id,
        bolt11: pr.to_string(),
        amount: params.amount as i64,
        state: InvoiceState::Pending as i32,
    };

    let created_invoice = state.db.insert_new_invoice(new_invoice)?;

    // save nostr zap request
    if let Some(request) = params.nostr {
        let new_zap = NewZap {
            request,
            event_id: None,
        };
        state.db.insert_new_zap(new_zap)?;
    }

    // create subscription to operation
    let subscription = ln
        .subscribe_ln_receive(op_id)
        .await
        .expect("subscribing to a just created operation can't fail");

    spawn_invoice_subscription(
        state.clone(),
        created_invoice,
        client,
        user.clone(),
        subscription,
    )
    .await;

    let verify_url = format!("{}/lnurlp/{}/verify/{}", state.domain, user.name, op_id);

    Ok(LnurlCallbackResponse {
        pr: pr.to_string(),
        success_action: None,
        status: LnurlStatus::Ok,
        reason: None,
        verify: verify_url.parse()?,
        routes: Some(vec![]),
    })
}

pub async fn verify(
    state: &State,
    name: String,
    op_id: String,
) -> anyhow::Result<LnurlVerifyResponse> {
    let invoice = state
        .db
        .get_invoice_by_op_id(op_id)?
        .map_or(Err(anyhow::anyhow!("NotFound")), Ok)?;

    let user = state
        .db
        .get_user_by_name(name)?
        .map_or(Err(anyhow::anyhow!("NotFound")), Ok)?;

    if invoice.app_user_id != user.id {
        return Err(anyhow::anyhow!("NotFound"));
    }

    let verify_response = LnurlVerifyResponse {
        status: LnurlStatus::Ok,
        settled: invoice.state == InvoiceState::Settled as i32,
        preimage: "".to_string(), // TODO: figure out how to get the preimage from fedimint client
        pr: invoice.bolt11,
    };

    Ok(verify_response)
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests_integration {
    use nostr::{key::FromSkStr, Keys};
    use secp256k1::Secp256k1;
    use std::sync::Arc;

    use crate::{
        db::setup_db, lnurlp::well_known_lnurlp, mint::MockMultiMintWrapperTrait,
        models::app_user::NewAppUser, register::BlindSigner, State,
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

        // create blind signer
        let signer = BlindSigner::derive(&[0u8; 32], 0, 0);

        let mock_mm = Arc::new(mock_mm);
        let state = State {
            db: db.clone(),
            mm: mock_mm,
            secp: Secp256k1::new(),
            nostr,
            auth_pk: signer.pk,
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
