use async_trait::async_trait;
use fedimint_client::ClientHandleArc;
use fedimint_core::{api::InviteCode, config::FederationId};
use fedimint_ln_client::LightningClientModule;
use fedimint_ln_common::LightningGateway;
use log::error;
use std::collections::HashMap;
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
    async fn get_gateway(&self, id: &FederationId) -> Option<LightningGateway>;
}

#[derive(Clone)]
struct MultiMintWrapper {
    fm: Arc<RwLock<MultiMint>>,
    /// Our preferred lightning gateway for each federation
    gateways: Arc<RwLock<HashMap<FederationId, LightningGateway>>>,
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

        if let Some(gateway) = select_gateway(&client).await {
            self.gateways.write().await.insert(id, gateway);
        } else {
            error!("No suitable gateway found for federation {id}");
        }

        Ok(())
    }

    async fn get_gateway(&self, id: &FederationId) -> Option<LightningGateway> {
        let lock = self.gateways.read().await;
        lock.get(id).cloned()
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
        gateways: Arc::new(RwLock::new(HashMap::new())),
    };

    Ok(Arc::new(mmw))
}

pub(crate) async fn select_gateway(client: &ClientHandleArc) -> Option<LightningGateway> {
    let ln = client.get_first_module::<LightningClientModule>();
    let mut gateway_id = None;
    for gateway in ln.list_gateways().await {
        // first try to find a vetted gateway
        if gateway.vetted {
            gateway_id = Some(gateway.info.gateway_id);
            break; // if vetted gateway found, use it
        }

        // if no vetted gateway found, try to find a gateway with reasonable fees
        let fees = gateway.info.fees;
        if fees.base_msat >= 1_000 && fees.proportional_millionths >= 100 {
            gateway_id = Some(gateway.info.gateway_id);
        }
    }

    if let Some(gateway_id) = gateway_id {
        if let Some(gateway) = ln.select_gateway(&gateway_id).await {
            return Some(gateway);
        }
    }

    None
}
