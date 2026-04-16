/*
 * Copyright 2026 Cybersecurity Lab, University of Udine or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
