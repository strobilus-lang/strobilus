use cedar_policy::{Authorizer, Context, Decision, Entities, PolicySet, Request};

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
        principal: &str,
        action: &str,
        resource: &str,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        let principal_entity = principal.parse()?;
        let action_entity = action.parse()?;
        let resource_entity = resource.parse()?;

        let request = Request::new(
            principal_entity,
            action_entity,
            resource_entity,
            Context::empty(),
            None,
        )?;

        Ok(self.engine
            .is_authorized(&request, &self.policy_set, &self.entities).decision())
    }
}
