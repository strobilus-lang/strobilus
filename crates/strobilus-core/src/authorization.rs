use cedar_policy::{Decision, Entities, PolicySet};

use crate::entity_store::factory::create_entity_store;
use crate::entity_store::EntityStore;
use crate::policy_engine::PolicyEngine;

pub struct Authorizer {
    engine: PolicyEngine,
    entity_store: Box<dyn EntityStore>,
}

impl Authorizer {
    pub fn new(policies: PolicySet, entities: Entities) -> Self {
        let entity_store = create_entity_store(entities);
        let engine = PolicyEngine::new(policies, entity_store.entities());

        Self {
            engine,
            entity_store,
        }
    }

    pub fn is_authorized(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        self.engine.evaluate(principal, action, resource)
    }

/*     // Passare le annotazioni delle policy
    pub fn execute_obbligations(self, decision: Decision) -> () {
        execute_obbligation(decision, self.entity_store);
    }

    pub fn store(self) -> Box<dyn EntityStore> {
        self.entity_store
    } */
}
