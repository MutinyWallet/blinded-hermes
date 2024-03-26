use async_trait::async_trait;
use fedimint_client::ClientHandleArc;
use fedimint_core::{api::InviteCode, config::FederationId};
use fedimint_ln_client::LightningClientModule;
use fedimint_ln_common::LightningGateway;
use log::error;
use std::collections::HashMap;
use std::time::Duration;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[cfg(test)]
use mockall::automock;
use multimint::MultiMint;

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait MultiMintWrapperTrait {
    async fn check_has_federation(&self, id: FederationId) -> bool;
    async fn get_federation_client(&self, id: FederationId) -> Option<ClientHandleArc>;
    async fn register_new_federation(&self, invite_code: InviteCode) -> anyhow::Result<()>;
}

#[derive(Clone)]
struct MultiMintWrapper {
    fm: Arc<RwLock<MultiMint>>,
}

#[async_trait]
impl MultiMintWrapperTrait for MultiMintWrapper {
    async fn check_has_federation(&self, id: FederationId) -> bool {
        self.fm.read().await.clients.lock().await.contains_key(&id)
    }

    async fn get_federation_client(&self, id: FederationId) -> Option<ClientHandleArc> {
        self.fm.read().await.clients.lock().await.get(&id).cloned()
    }

    async fn register_new_federation(&self, invite_code: InviteCode) -> anyhow::Result<()> {
        let id = self
            .fm
            .write()
            .await
            .register_new(invite_code, None)
            .await?;

        let client = self
            .get_federation_client(id)
            .await
            .expect("just registered");

        // update gateway cache, so we can find the best gateways
        let ln = client.get_first_module::<LightningClientModule>();
        if let Err(e) = ln.update_gateway_cache(true).await {
            error!("Failed to update gateway cache: {e}");
        }

        Ok(())
    }
}

pub(crate) async fn setup_multimint(
    db_path: PathBuf,
) -> anyhow::Result<Arc<dyn MultiMintWrapperTrait + Send + Sync>> {
    let mm = MultiMint::new(db_path).await?;

    let clients = mm.clients.lock().await;
    let mut gateways = HashMap::with_capacity(clients.len());

    // select gateway for each federation
    for (id, client) in clients.iter() {
        // update gateway cache, so we can find the best gateways
        let ln = client.get_first_module::<LightningClientModule>();
        if let Err(e) = ln.update_gateway_cache(true).await {
            error!("Failed to update gateway cache: {e}");
        }

        match select_gateway(client).await {
            Some(gateway) => {
                gateways.insert(*id, gateway);
            }
            None => {
                error!("No suitable gateway found for federation {id}");
            }
        }
    }
    drop(clients);

    let mmw = MultiMintWrapper {
        fm: Arc::new(RwLock::new(mm)),
    };

    let mmw = Arc::new(mmw);

    // spawn thread to update gateways periodically, check every hour
    let mmw_clone = mmw.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60 * 60)).await;
            let mm = mmw_clone.fm.read().await;
            let clients = mm.clients.lock().await;
            for (_, client) in clients.iter() {
                let ln = client.get_first_module::<LightningClientModule>();
                if let Err(e) = ln.update_gateway_cache(true).await {
                    error!("Failed to update gateway cache: {e}");
                }
            }
        }
    });

    Ok(mmw)
}

pub(crate) async fn select_gateway(client: &ClientHandleArc) -> Option<LightningGateway> {
    let ln = client.get_first_module::<LightningClientModule>();
    let mut selected_gateway = None;
    for gateway in ln.list_gateways().await {
        // first try to find a vetted gateway
        if gateway.vetted {
            // if we can select the gateway, return it
            if let Some(gateway) = ln.select_gateway(&gateway.info.gateway_id).await {
                return Some(gateway);
            }
        }

        // if no vetted gateway found, try to find a gateway with reasonable fees
        let fees = gateway.info.fees;
        if fees.base_msat >= 1_000 && fees.proportional_millionths >= 100 {
            if let Some(g) = ln.select_gateway(&gateway.info.gateway_id).await {
                selected_gateway = Some(g);
            }
        }
    }

    selected_gateway
}
