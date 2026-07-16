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

use std::{
    collections::{BTreeMap, HashSet},
    iter,
    sync::Arc,
};

use cedar_policy_core::{
    ast::{Entity, EntityUID, PartialValue, Value},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
};

use smol_str::SmolStr;

use crate::entities::{builder::EntityBuilder, error::EntityStoreError};

/// All the operations you can perform *via* an EntityStore,
/// each taking the `EntityUID` to identify the target.
/// At this moment, the values of Attributes are represented as `Value`.
/// In the future, for handle templating, we will switch to PartialValue
/// as the original Entities provided by Cedar.
pub trait EntityStore {
    /// Mutate the direct‐parent set of a given entity.
    fn add_parent(&mut self, uid: &EntityUID, parent: EntityUID) -> Result<(), EntityStoreError>;
    fn remove_parent(
        &mut self,
        uid: &EntityUID,
        parent: &EntityUID,
    ) -> Result<(), EntityStoreError>;

    /// Mutate the entity itself.
    fn update_entity(
        &mut self,
        uid: EntityUID,
        attrs: BTreeMap<SmolStr, PartialValue>,
        anc: HashSet<EntityUID>,
        tags: BTreeMap<SmolStr, PartialValue>,
    ) -> Result<(), EntityStoreError>;
    fn remove_entity(&mut self, uid: &EntityUID) -> Result<(), EntityStoreError>;

    /// Mutate attributes.
    fn update_attribute(
        &mut self,
        uid: &EntityUID,
        key: SmolStr,
        value: Value,
    ) -> Result<(), EntityStoreError>;
    fn remove_attribute(&mut self, uid: &EntityUID, key: &SmolStr) -> Result<(), EntityStoreError>;

    /// Consume the store and produce Cedar’s `Entities` in one bulk step.
    fn into_entities(self) -> Entities;

    /*     /// Mutate the indirect‐ancestor set.
    fn add_indirect_ancestor(&mut self, uid: &EntityUID, anc: EntityUID);
    fn remove_indirect_ancestor(&mut self, uid: &EntityUID, anc: &EntityUID);

    /// Mutate tags.
    fn add_tag(&mut self, uid: &EntityUID, key: SmolStr, value: Value);
    fn remove_tag(&mut self, uid: &EntityUID, key: &SmolStr); */
}

#[derive(Debug, Default, Clone)]
pub struct BasicEntityStore {
    inner: Entities,
}

impl BasicEntityStore {
    pub fn new(entities: Entities) -> Self {
        Self { inner: entities }
    }

    fn entity(&self, uid: &EntityUID) -> Option<Entity> {
        let entity_deref = self.inner.entity(uid);

        match entity_deref {
            cedar_policy_core::entities::Dereference::Data(content) => Some(content.clone()),
            _ => None,
        }
    }

    fn update_entity(&mut self, entity: Entity) -> Result<(), EntityStoreError> {
        match self.inner.clone().upsert_entities(
            iter::once(Arc::new(entity)),
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::none(),
        ) {
            Ok(new_entities) => Ok(self.inner = new_entities),
            Err(_) => Err(EntityStoreError::BuildEntities),
        }
    }
}

impl EntityStore for BasicEntityStore {
    fn add_parent(&mut self, uid: &EntityUID, parent: EntityUID) -> Result<(), EntityStoreError> {
        if let Some(mut entity) = self.entity(uid) {
            entity.add_parent(parent);
            self.update_entity(entity)?;
            Ok(())
        } else {
            Err(EntityStoreError::EntityNotFound(uid.clone()))
        }
    }

    fn remove_parent(
        &mut self,
        uid: &EntityUID,
        parent: &EntityUID,
    ) -> Result<(), EntityStoreError> {
        if let Some(mut entity) = self.entity(uid) {
            entity.remove_parent(parent);
            self.update_entity(entity)?;
            Ok(())
        } else {
            Err(EntityStoreError::EntityNotFound(uid.clone()))
        }
    }

    fn update_entity(
        &mut self,
        uid: EntityUID,
        attrs: BTreeMap<SmolStr, PartialValue>,
        parents: HashSet<EntityUID>,
        tags: BTreeMap<SmolStr, PartialValue>,
    ) -> Result<(), EntityStoreError> {
        let mut builder = EntityBuilder::new(uid);
        builder
            .with_attrs(attrs)
            .with_parents(parents)
            .with_tags(tags);
        self.update_entity(builder.build())
    }

    fn remove_entity(&mut self, uid: &EntityUID) -> Result<(), EntityStoreError> {
        if let Some(_) = self.entity(uid) {
            if let Ok(new_entities) = self
                .inner
                .clone()
                .remove_entities(iter::once(uid.clone()), TCComputation::ComputeNow)
            {
                Ok(self.inner = new_entities)
            } else {
                Err(EntityStoreError::BuildEntities)
            }
        } else {
            Err(EntityStoreError::EntityNotFound(uid.clone()))
        }
    }

    fn update_attribute(
        &mut self,
        uid: &EntityUID,
        key: SmolStr,
        value: Value,
    ) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entity(uid) {
            let mut builder = EntityBuilder::from_entity_ref(&entity);
            builder.add_attr(key, PartialValue::from(value));
            self.update_entity(builder.build())?;
            Ok(())
        } else {
            Err(EntityStoreError::EntityNotFound(uid.clone()))
        }
    }

    fn remove_attribute(&mut self, uid: &EntityUID, key: &SmolStr) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entity(uid) {
            let mut builder = EntityBuilder::from_entity_ref(&entity);
            builder.remove_attr(key);
            self.update_entity(builder.build())?;
            Ok(())
        } else {
            Err(EntityStoreError::EntityNotFound(uid.clone()))
        }
    }

    fn into_entities(self) -> Entities {
        self.inner
    }

    /*
    fn add_indirect_ancestor(&mut self, uid: &EntityUID, anc: EntityUID) {
        todo!()
    }

    fn remove_indirect_ancestor(&mut self, uid: &EntityUID, anc: &EntityUID) {
        todo!()
    }

    fn add_tag(&mut self, uid: &EntityUID, key: SmolStr, value: Value) {
        todo!()
    }

    fn remove_tag(&mut self, uid: &EntityUID, key: &SmolStr) {
        todo!()
    }
    */
}


pub trait OptimisticEntityStore {
    fn get_entities_ref(&self) -> &Entities;
}

impl OptimisticEntityStore for BasicEntityStore {
    fn get_entities_ref(&self) -> &Entities {
        &self.inner
    }
}

