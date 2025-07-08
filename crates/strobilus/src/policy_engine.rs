use cedar_policy_core::{
    ast::{PolicySet, Request},
    authorizer::{Authorizer, Decision},
    entities::Entities,
};

pub struct PolicyEngine {
    engine: Authorizer,
    policy_set: PolicySet,
    entities: Entities,
}

impl PolicyEngine {
    pub fn new(policy_set: PolicySet, entities: Entities) -> Self {
        let engine = Authorizer::new();
        Self {
            engine,
            policy_set,
            entities,
        }
    }

    pub fn evaluate(
        &self,
        request: Request
    ) -> Result<Decision, Box<dyn std::error::Error>> {

        Ok(self
            .engine
            .is_authorized(request, &self.policy_set, &self.entities)
            .decision)
    }
}
