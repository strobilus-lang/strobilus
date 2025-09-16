use cedar_policy_core::{
    ast::{PolicySet, Request},
    authorizer::{Authorizer as CedarAuthorizer, Decision},
    entities::Entities,
};

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    engine: CedarAuthorizer,
    policy_set: PolicySet,
}

impl PolicyEngine {
    pub fn new(policy_set: PolicySet) -> Self {
        let engine = CedarAuthorizer::new();
        Self {
            engine,
            policy_set
        }
    }

    pub fn evaluate(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<Decision, Box<dyn std::error::Error>> {

        Ok(self
            .engine
            .is_authorized(request.clone(), &self.policy_set, entities)
            .decision)
    }
}
