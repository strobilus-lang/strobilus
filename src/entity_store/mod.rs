use cedar_policy_core::{ast::{Entity, EntityUID, Value}, entities::{Entities, EntityJsonParser, NoEntitiesSchema}, extensions::Extensions};
use std::collections::{HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum EntityStoreError {
    #[error("Entity not found: {0}")]
    NotFound(EntityUID),
    #[error("Invalid entity: {0}")]
    Invalid(String),
    #[error("Operation failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct EntityStore {
    entities: HashMap<EntityUID, Entity>,
}

impl EntityStore {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    pub fn from_entities(entities_data: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parse_entities = EntityJsonParser::<cedar_policy_core::entities::NoEntitiesSchema>::new(
            None,
            Extensions::none(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        )
        .from_json_str(entities_data)?;

        let entities = parse_entities
            .into_iter()
            .map(|entity| (entity.uid().clone(), entity))
            .collect();
        
        Ok(Self {
            entities,
        })
    }

    pub fn entities(&self) -> Result<Entities, cedar_policy::entities_errors::EntitiesError> {
        Entities::from_entities(
            self.entities.values().cloned(),
            None::<&NoEntitiesSchema>,
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::none(),
        )
    }

    pub fn update_entity(
        &mut self,
        uid: EntityUID,
        attrs: HashMap<String, cedar_policy_core::ast::Value>,
        ancestors: HashSet<EntityUID>,
    ) -> Result<Self, EntityStoreError> {
        todo!()
    }

    pub fn remove_entity(&mut self, uid: &EntityUID) -> Result<Self, EntityStoreError> {
        todo!()
    }

    pub fn add_parent(
        &mut self,
        uid: &EntityUID,
        ancestor: EntityUID,
    ) -> Result<Self, EntityStoreError> {
        todo!()
    }

    pub fn remove_parent(
        &mut self,
        uid: &EntityUID,
        ancestor: &EntityUID,
    ) -> Result<Self, EntityStoreError> {
        todo!()
    }

    pub fn update_attribute(
        &mut self,
        uid: &EntityUID,
        attr: &str,
        val: Value,
    ) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entities.get_mut(uid) {
            //println!("--- Considering attr {}", attr);
            if let Some(_existing_value) = entity.get(attr) {
                // You cannot assign directly to &existing_value since it's an immutable reference.
                // Instead, update the entity's attribute map and re-insert the entity.
                let (uid, mut attrs, ancestors, _tags) = entity.clone().into_inner();
                attrs.insert(attr.into(), val.into());
                println!("--- Updating attribute: {} for entity: {:?}", attr, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid, attrs, ancestors)
                );
                Ok(())
            } else {
                let (_, mut attrs, ancestors, _tags) = entity.clone().into_inner();
                attrs.insert(attr.into(), val.into());
                 println!("--- Creating attribute: {} for entity: {:?}", attr, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid.clone(), attrs, ancestors)
                );
                Ok(())
            }
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
    }

    pub fn remove_attribute(&mut self, uid: &EntityUID, attr: &str) -> Result<Self, EntityStoreError> {
        todo!()
    }
}
