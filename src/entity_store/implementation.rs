use cedar_policy::{Entity, EntityUid, RestrictedExpression};

use super::api::{EntityStore, EntityStoreError};
use std::collections::{HashMap, HashSet};

pub struct InMemoryEntityStore {
    entities: HashMap<EntityUid, Entity>,
}

impl InMemoryEntityStore {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    fn insert_entity(
        &mut self,
        uid: &EntityUid,
        attrs: HashMap<String, RestrictedExpression>,
        ancestors: HashSet<EntityUid>,
    ) -> Result<(), EntityStoreError> {
        let _entity = Entity::new(uid.clone(), attrs, ancestors)
            .map_err(|e| EntityStoreError::Invalid(e.to_string()))?;
        self.entities.insert(uid.clone(), _entity);
        Ok(())
    }

    fn get_entity(
        &mut self,
        uid: &EntityUid,
    ) -> Result<
        (
            EntityUid,
            HashMap<String, RestrictedExpression>,
            HashSet<EntityUid>,
        ),
        EntityStoreError,
    > {
        self.entities
            .get(uid)
            .cloned()
            .map(|entity| entity.into_inner())
            .ok_or_else(|| EntityStoreError::NotFound(uid.clone()))
    }
}

impl EntityStore for InMemoryEntityStore {
    fn update_entity(
        &mut self,
        uid: EntityUid,
        attrs: HashMap<String, RestrictedExpression>,
        ancestors: HashSet<EntityUid>,
    ) -> Result<(), EntityStoreError> {
        self.insert_entity(&uid, attrs, ancestors)
    }

    fn remove_entity(&mut self, uid: &EntityUid) -> Result<(), EntityStoreError> {
        self.entities
            .remove(uid)
            .ok_or_else(|| EntityStoreError::NotFound(uid.clone()))?;
        Ok(())
    }

    fn add_parent(&mut self, uid: &EntityUid, ancestor: EntityUid) -> Result<(), EntityStoreError> {
        let (_uid, attrs, mut ancestors) = self.get_entity(uid)?;

        if !ancestors.contains(&ancestor) {
            ancestors.insert(ancestor);
        }

        self.insert_entity(&_uid, attrs, ancestors)
    }

    fn remove_parent(
        &mut self,
        uid: &EntityUid,
        parent: &EntityUid,
    ) -> Result<(), EntityStoreError> {
        let (_uid, attrs, mut ancestors) = self.get_entity(uid)?;

        ancestors.retain(|p| p != parent);

        self.insert_entity(&_uid, attrs, ancestors)
    }

    fn update_attribute(
        &mut self,
        uid: &EntityUid,
        key: &str,
        val: RestrictedExpression,
    ) -> Result<(), EntityStoreError> {
        let (_uid, mut attrs, ancestors) = self.get_entity(uid)?;

        attrs.insert(key.to_string(), val);

        self.insert_entity(&_uid, attrs, ancestors)
    }

    fn remove_attribute(&mut self, uid: &EntityUid, key: &str) -> Result<(), EntityStoreError> {
        let (_uid, mut attrs, ancestors) = self.get_entity(uid)?;

        attrs.remove(key);

        self.insert_entity(&_uid, attrs, ancestors)
    }
}
