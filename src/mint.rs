use std::{path::PathBuf, sync::Arc};

#[cfg(test)]
use mockall::automock;
use multimint::MultiMint;

#[cfg_attr(test, automock)]
pub(crate) trait MultiMintWrapperTrait {}

#[derive(Clone)]
pub(crate) struct MultiMintWrapper {
    fm: MultiMint,
}

impl MultiMintWrapperTrait for MultiMintWrapper {}

pub(crate) async fn setup_multimint(
    db_path: PathBuf,
) -> anyhow::Result<Arc<dyn MultiMintWrapperTrait + Send + Sync>> {
    let fm = MultiMint::new(db_path).await?;
    let mmw = MultiMintWrapper { fm };

    Ok(Arc::new(mmw))
}
