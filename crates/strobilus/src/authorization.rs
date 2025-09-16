use cedar_policy_core::{
    ast::{Context, PolicySet, Request, RequestSchemaAllPass},
    authorizer::Decision,
    entities::Entities,
    extensions::Extensions,
};
use strobilus_core::{ast::CommandSet, interpreter::Interpreter};

use crate::policy_engine::PolicyEngine;

#[derive(Debug, Clone)]
pub struct Authorizer {
    engine: PolicyEngine,
    interpreter: Interpreter,
}

impl Authorizer {
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        let engine = PolicyEngine::new(policies);
        let interpreter = Interpreter::new(commands, entities);

        Self {
            engine,
            interpreter,
        }
    }

    pub fn entities(self) -> Entities {
        self.interpreter.entity_store()
    }

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
        &mut self,
        request: &Request,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        let entities = self.interpreter.clone().entity_store();
        let decision = self.engine.evaluate(request, &entities)?;
        self.interpreter.execute(request, decision)?;

        Ok(decision)
    }
}
