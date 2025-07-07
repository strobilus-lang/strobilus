use cedar_policy_core::{
    ast::{Entity, EntityUID, PartialValue, Value},
    entities::{Entities, EntityJsonParser, NoEntitiesSchema},
    extensions::Extensions,
};
use smol_str::SmolStr;
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
        let parse_entities =
            EntityJsonParser::<cedar_policy_core::entities::NoEntitiesSchema>::new(
                None,
                Extensions::none(),
                cedar_policy_core::entities::TCComputation::ComputeNow,
            )
            .from_json_str(entities_data)?;

        let entities = parse_entities
            .into_iter()
            .map(|entity| (entity.uid().clone(), entity))
            .collect();

        Ok(Self { entities })
    }

    pub fn entities(&self) -> Result<Entities, Box<dyn std::error::Error>> {
        Ok(Entities::from_entities(
            self.entities.values().cloned(),
            None::<&NoEntitiesSchema>,
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::none(),
        )?)
    }

    pub fn update_entity(
        &mut self,
        uid: EntityUID,
        attrs: HashMap<SmolStr, cedar_policy_core::ast::Value>,
        ancestors: HashSet<EntityUID>,
        tags: HashMap<SmolStr, PartialValue>
    ) -> Result<(), EntityStoreError> {
        // Convert Value to RestrictedExpr for each attribute
        let attrs_restricted: HashMap<SmolStr, cedar_policy_core::ast::RestrictedExpr> = attrs
            .into_iter()
            .map(|(k, v)| {
            let expr = cedar_policy_core::ast::RestrictedExpr::from(v);
            (k, expr)
            })
            .collect();
        // Convert PartialValue to RestrictedExpr for each tag, propagating errors
        let tags_restricted: Result<HashMap<SmolStr, cedar_policy_core::ast::RestrictedExpr>, _> = tags
            .into_iter()
            .map(|(k, v)| {
            cedar_policy_core::ast::RestrictedExpr::try_from(v).map(|expr| (k, expr))
            })
            .collect();
        let tags_restricted = tags_restricted
            .map_err(|e| EntityStoreError::Invalid(format!("Tag conversion failed: {}", e)))?;
        println!(
            "--- {} entity: {:?}",
            if self.entities.contains_key(&uid) { "Updating" } else { "Creating" },
            uid
        );
        self.entities.insert(
            uid.clone(),
            Entity::new(
            uid.clone(),
            attrs_restricted,
            ancestors,
            tags_restricted,
            Extensions::none(),
            ).map_err(|e| EntityStoreError::Invalid(format!("Entity creation failed: {}", e)))?,
        );
        Ok(())
    }

    pub fn remove_entity(&mut self, uid: &EntityUID) -> Result<(), EntityStoreError> {
        if self.entities.remove(uid).is_some() {
            println!("--- Removing entity: {:?}", uid);
            Ok(())
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
    }

    pub fn add_parent(
        &mut self,
        uid: &EntityUID,
        ancestor: EntityUID,
    ) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entities.get_mut(uid) {
            let (uid, attrs, mut ancestors, _tags) = entity.clone().into_inner();
            if ancestors.insert(ancestor.clone()) {
                println!("--- Adding parent: {:?} to entity: {:?}", ancestor, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid, attrs, ancestors),
                );
                Ok(())
            } else {
                Err(EntityStoreError::Invalid(format!(
                    "Parent '{}' already exists for entity '{}'",
                    ancestor, uid
                )))
            }
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
    }

    pub fn remove_parent(
        &mut self,
        uid: &EntityUID,
        ancestor: &EntityUID,
    ) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entities.get_mut(uid) {
            let (uid, attrs, mut ancestors, _tags) = entity.clone().into_inner();
            if ancestors.remove(ancestor) {
                println!("--- Removing parent: {:?} from entity: {:?}", ancestor, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid, attrs, ancestors),
                );
                Ok(())
            } else {
                Err(EntityStoreError::Invalid(format!(
                    "Parent '{}' does not exist for entity '{}'",
                    ancestor, uid
                )))
            }
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
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
                    Entity::new_with_attr_partial_value(uid, attrs, ancestors),
                );
                Ok(())
            } else {
                let (_, mut attrs, ancestors, _tags) = entity.clone().into_inner();
                attrs.insert(attr.into(), val.into());
                println!("--- Creating attribute: {} for entity: {:?}", attr, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid.clone(), attrs, ancestors),
                );
                Ok(())
            }
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
    }

    pub fn remove_attribute(
        &mut self,
        uid: &EntityUID,
        attr: &str,
    ) -> Result<(), EntityStoreError> {
        if let Some(entity) = self.entities.get_mut(uid) {
            //println!("--- Considering attr {}", attr);
            if entity.get(attr).is_some() {
                let (uid, mut attrs, ancestors, _tags) = entity.clone().into_inner();
                attrs.remove(attr);
                println!("--- Removing attribute: {} for entity: {:?}", attr, uid);
                self.entities.insert(
                    uid.clone(),
                    Entity::new_with_attr_partial_value(uid, attrs, ancestors),
                );
                Ok(())
            } else {
                Err(EntityStoreError::Invalid(format!(
                    "Attribute '{}' not found for entity '{}'",
                    attr, uid
                )))
            }
        } else {
            Err(EntityStoreError::NotFound(uid.clone()))
        }
    }
}
