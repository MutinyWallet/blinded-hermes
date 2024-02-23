use async_trait::async_trait;
use fedimint_core::{api::InviteCode, config::FederationId};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[cfg(test)]
use mockall::automock;
use multimint::MultiMint;

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait MultiMintWrapperTrait {
    async fn check_has_federation(&self, id: FederationId) -> bool;
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

    async fn register_new_federation(&self, invite_code: InviteCode) -> anyhow::Result<()> {
        self.fm
            .write()
            .await
            .register_new(invite_code, false)
            .await?;
        Ok(())
    }
}

pub(crate) async fn setup_multimint(
    db_path: PathBuf,
) -> anyhow::Result<Arc<dyn MultiMintWrapperTrait + Send + Sync>> {
    let fm = Arc::new(RwLock::new(MultiMint::new(db_path).await?));
    let mmw = MultiMintWrapper { fm };

    Ok(Arc::new(mmw))
}
