//! AgentX domain concepts. This module intentionally has no filesystem or CLI dependencies.
pub mod environment {
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Target {
        pub name: String,
    }
}
