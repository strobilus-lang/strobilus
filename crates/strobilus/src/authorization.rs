use cedar_policy_core::{ast::{Context, PolicySet, Request, RequestSchemaAllPass}, authorizer::Decision, entities::Entities, extensions::Extensions};
use strobilus_core::entity_store::EntityStore;

use crate::policy_engine::PolicyEngine;

pub struct Authorizer {
    engine: PolicyEngine,
    entity_store: EntityStore,
}

impl Authorizer {
    pub fn new(policies: PolicySet, entities: Entities) -> Self {
        let entity_store = EntityStore::from_entities(entities);
        let engine = PolicyEngine::new(
            policies,
            entity_store.entities().expect("Failed to get entities"),
        );

        Self {
            engine,
            entity_store,
        }
    }

    // TODO: Refactor this function to a struct standalone
    //       that can be used in the interpreter.
    pub fn request(
        principal: &str,
        action: &str,
        resource: &str,
    ) -> Result<Request, Box<dyn std::error::Error>> {
        let principal_entity = (principal.parse()?, None);
        let action_entity = (action.parse()?, None);
        let resource_entity = (resource.parse()?, None);

        Ok(Request::new::<RequestSchemaAllPass>(
            principal_entity,
            action_entity,
            resource_entity,
            Context::empty(),
            None,
            Extensions::none(),
        )?)
    }

    pub fn is_authorized(
        &self,
        request: Request
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        self.engine.evaluate(request)
            .map_err(|e| format!("Failed to evaluate request: {}", e).into())
    }
}
