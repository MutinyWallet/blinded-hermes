use std::{collections::HashMap, str::FromStr};

use anyhow::{anyhow, Result};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_core::{config::FederationId, task::spawn};
use fedimint_ln_client::{LightningClientModule, LnReceiveState};
use futures::StreamExt;
use itertools::Itertools;
use log::{error, info};
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
pub(crate) async fn handle_pending_invoices(state: &State) -> Result<()> {
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
                    // Check if invoice has expired
                    if invoice.bolt11().is_expired() {
                        state
                            .db
                            .set_invoice_state(invoice, InvoiceState::Cancelled as i32)?;
                        continue;
                    }

                    // Create subscription to operation if it exists
                    if let Ok(subscription) = ln
                        .subscribe_ln_receive(invoice.op_id.parse().expect("invalid op_id"))
                        .await
                    {
                        let user = state
                            .db
                            .get_user_by_id(invoice.app_user_id)?
                            .ok_or(anyhow!("no user"))?;
                        spawn_invoice_subscription(
                            state.clone(),
                            invoice,
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
    user: AppUser,
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
                    match notify_user(&nostr, &state, &i, user).await {
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
    nostr: &Client,
    state: &State,
    invoice: &Invoice,
    user: AppUser,
) -> Result<()> {
    let zap = state.db.get_zap_by_id(invoice.id)?;

    let dm = nostr
        .send_direct_msg(
            ::nostr::PublicKey::from_str(&user.pubkey)?,
            json!({
                "federation_id": invoice.federation_id,
                "tweak_index": invoice.user_invoice_index,
                "amount": invoice.amount,
                "bolt11": invoice.bolt11,
                "preimage": invoice.preimage,
                "zap_request": zap.as_ref().map(|z| z.request.clone()),
            })
            .to_string(),
            None,
        )
        .await?;

    // Send zap if needed
    if let Some(zap) = zap {
        let request = Event::from_json(&zap.request)?;
        let event = EventBuilder::zap_receipt(
            invoice.bolt11.to_string(),
            Some(invoice.preimage.clone()),
            request,
        )
        .to_event(&state.nostr_sk)?;

        let event_id = nostr.send_event(event).await?;
        info!("Broadcasted zap {event_id}!");

        state.db.set_zap_event_id(zap, event_id.to_string())?;
    }

    info!("Sent nostr dm: {dm}");
    Ok(())
}
