pub mod api;
#[cfg(feature = "local-embedding")]
pub mod local;
pub mod mock;

pub use api::ApiEmbedder;
#[cfg(feature = "local-embedding")]
pub use local::LocalEmbedder;
pub use mock::MockEmbedder;
