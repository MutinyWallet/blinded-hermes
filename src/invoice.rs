use std::{collections::HashMap, str::FromStr, time::Duration};

use anyhow::{anyhow, Result};
use fedimint_client::{oplog::UpdateStreamOrOutcome, ClientArc};
use fedimint_core::{config::FederationId, core::OperationId, task::spawn, Amount};
use fedimint_ln_client::{LightningClientModule, LnReceiveState};
use fedimint_mint_client::{MintClientModule, OOBNotes};
use futures::StreamExt;
use itertools::Itertools;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use log::{error, info};
use nostr::hashes::Hash;
use nostr::key::{Secp256k1, SecretKey};
use nostr::prelude::rand::rngs::OsRng;
use nostr::prelude::rand::RngCore;
use nostr::secp256k1::XOnlyPublicKey;
use nostr::{bitcoin::hashes::sha256::Hash as Sha256, Keys};
use nostr::{Event, EventBuilder, JsonUtil};
use nostr_sdk::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    models::{app_user::AppUser, invoice::Invoice},
    State,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum InvoiceState {
    /// The invoice is pending payment.
    Pending = 0,
    /// The invoice has been paid and settled.
    Settled = 1,
    /// The invoice has been cancelled or expired.
    Cancelled = 2,
}

/// Starts subscription for all pending invoices from previous run
pub(crate) async fn handle_pending_invoices(state: State) -> Result<()> {
    let invoices = state.db.get_pending_invoices()?;

    // Group invoices by federation_id
    let invoices_by_federation = invoices
        .into_iter()
        .group_by(|i| i.federation_id.clone())
        .into_iter()
        .map(|(federation_id, invs)| (federation_id, invs.collect::<Vec<_>>()))
        .collect::<HashMap<_, _>>();

    for (federation_id, invoices) in invoices_by_federation {
        // Get the corresponding multimint client for the federation_id
        if let Ok(federation_id) = FederationId::from_str(&federation_id) {
            if let Some(client) = state.mm.get_federation_client(federation_id).await {
                let ln = client.get_first_module::<LightningClientModule>();
                for invoice in invoices {
                    // Create subscription to operation if it exists
                    if let Ok(subscription) = ln
                        .subscribe_ln_receive(invoice.op_id.parse().expect("invalid op_id"))
                        .await
                    {
                        let user = state
                            .db
                            .get_user_by_id(invoice.app_user_id)?
                            .map_or(Err(anyhow!("no user")), Ok)?;
                        spawn_invoice_subscription(
                            state.clone(),
                            invoice,
                            client.clone(),
                            user.clone(),
                            subscription,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) async fn spawn_invoice_subscription(
    state: State,
    i: Invoice,
    client: ClientArc,
    userrelays: AppUser,
    subscription: UpdateStreamOrOutcome<LnReceiveState>,
) {
    spawn("waiting for invoice being paid", async move {
        let nostr = state.nostr.clone();
        let mut stream = subscription.into_stream();
        while let Some(op_state) = stream.next().await {
            // TODO if anything fails here, try again
            match op_state {
                LnReceiveState::Canceled { reason } => {
                    error!("Payment canceled, reason: {:?}", reason);
                    match state
                        .db
                        .set_invoice_state(i, InvoiceState::Cancelled as i32)
                    {
                        Ok(_) => (),
                        Err(e) => {
                            error!("Error setting invoice as cancelled: {:?}", e);
                        }
                    }
                    break;
                }
                LnReceiveState::Claimed => {
                    info!("Payment claimed");
                    match notify_user(
                        client,
                        &nostr,
                        &state,
                        i.id,
                        i.amount as u64,
                        userrelays.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            match state.db.set_invoice_state(i, InvoiceState::Settled as i32) {
                                Ok(_) => (),
                                Err(e) => {
                                    error!("Error setting invoice as settled: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error notifying user of ecash: {:?}", e);
                        }
                    }

                    break;
                }
                _ => {}
            }
        }
    });
}

async fn notify_user(
    client: ClientArc,
    nostr: &Client,
    state: &State,
    id: i32,
    amount: u64,
    app_user_relays: AppUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let mint = client.get_first_module::<MintClientModule>();
    let (operation_id, notes) = mint
        .spend_notes(Amount::from_msats(amount), Duration::from_secs(604800), ())
        .await?;

    send_nostr_dm(nostr, &app_user_relays, operation_id, amount, notes).await?;

    // Send zap if needed
    if let Some(zap) = state.db.get_zap_by_id(id)? {
        let request = Event::from_json(zap.request.clone())?;
        let event = create_zap_event(request, amount, nostr.keys().await)?;

        let event_id = nostr.send_event(event).await?;
        info!("Broadcasted zap {event_id}!");

        state.db.set_zap_event_id(zap, event_id.to_string())?;
    }

    Ok(())
}

async fn send_nostr_dm(
    nostr: &Client,
    app_user_relays: &AppUser,
    operation_id: OperationId,
    amount: u64,
    notes: OOBNotes,
) -> Result<()> {
    let dm = nostr
        .send_direct_msg(
            XOnlyPublicKey::from_str(&app_user_relays.pubkey).unwrap(),
            json!({
                "operationId": operation_id,
                "amount": amount,
                "notes": notes.to_string(),
            })
            .to_string(),
            None,
        )
        .await?;

    info!("Sent nostr dm: {dm}");
    Ok(())
}

/// Creates a nostr zap event with a fake invoice
fn create_zap_event(request: Event, amt_msats: u64, nsec: Keys) -> Result<Event> {
    let preimage = &mut [0u8; 32];
    OsRng.fill_bytes(preimage);
    let invoice_hash = Sha256::hash(preimage);

    let payment_secret = &mut [0u8; 32];
    OsRng.fill_bytes(payment_secret);

    let priv_key_bytes = &mut [0u8; 32];
    OsRng.fill_bytes(priv_key_bytes);
    let private_key = SecretKey::from_slice(priv_key_bytes)?;

    let desc_hash = Sha256::hash(request.as_json().as_bytes());

    let fake_invoice = InvoiceBuilder::new(Currency::Bitcoin)
        .amount_milli_satoshis(amt_msats)
        .description_hash(desc_hash)
        .current_timestamp()
        .payment_hash(invoice_hash)
        .payment_secret(PaymentSecret(*payment_secret))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))?;

    let event = EventBuilder::new_zap_receipt(
        fake_invoice.to_string(),
        Some(hex::encode(preimage)),
        request,
    )
    .to_event(&nsec)?;

    Ok(event)
}
