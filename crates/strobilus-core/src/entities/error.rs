use cedar_policy_core::ast::EntityUID;
use smol_str::SmolStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntityStoreError {
    #[error("entity `{0}` does not exist")]
    EntityNotFound(EntityUID),

    #[error("entity `{0}` already exists")]
    EntityAlreadyExists(EntityUID),

    #[error("parent `{parent}` not found for entity `{child}`")]
    ParentNotFound {
        child: EntityUID,
        parent: EntityUID,
    },

    #[error("entity `{child}` already has parent `{parent}`")]
    ParentAlreadyExists {
        child: EntityUID,
        parent: EntityUID,
    },

    #[error("entity `{child}` does not have parent `{parent}`")]
    ParentDoesNotExist {
        child: EntityUID,
        parent: EntityUID,
    },

    #[error("cycle detected when adding `{parent}` as parent of `{child}`")]
    CycleDetected {
        child: EntityUID,
        parent: EntityUID,
    },

    #[error("attribute `{key}` not found on entity `{uid}`")]
    AttributeNotFound {
        uid: EntityUID,
        key: SmolStr,
    },

    #[error("attribute `{key}` already exists on entity `{uid}`")]
    AttributeAlreadyExists {
        uid: EntityUID,
        key: SmolStr,
    },

    #[error("invalid attribute value for `{key}` on entity `{uid}`")]
    InvalidAttributeValue {
        uid: EntityUID,
        key: SmolStr,
    },

    #[error("invalid ancestor relationship for entity `{0}`")]
    InvalidAncestor(EntityUID),

    #[error("failed to build Entities structure")]
    BuildEntities,
}
