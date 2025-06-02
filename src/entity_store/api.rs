use cedar_policy::{EntityUid, RestrictedExpression};
use std::collections::{HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum EntityStoreError {
    #[error("Entity not found: {0}")]
    NotFound(EntityUid),
    #[error("Invalid entity: {0}")]
    Invalid(String),
    #[error("Operation failed: {0}")]
    Failed(String),
}

pub trait EntityStore {
    fn update_entity(&mut self, uid: EntityUid, attrs: HashMap<String, RestrictedExpression>, parents: HashSet<EntityUid>) -> Result<(), EntityStoreError>;
    fn remove_entity(&mut self, uid: &EntityUid) -> Result<(), EntityStoreError>;

    fn add_parent(&mut self, uid: &EntityUid, parent: EntityUid) -> Result<(), EntityStoreError>;
    fn remove_parent(&mut self, uid: &EntityUid, parent: &EntityUid) -> Result<(), EntityStoreError>;

    fn update_attribute(&mut self, uid: &EntityUid, key: &str, val: RestrictedExpression) -> Result<(), EntityStoreError>;
    fn remove_attribute(&mut self, uid: &EntityUid, key: &str) -> Result<(), EntityStoreError>;
}
