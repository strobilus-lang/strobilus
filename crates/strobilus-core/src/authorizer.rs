use crate::{ast::CommandSet, interpreter::Interpreter};
use cedar_policy_core::{
    ast::{Context, PolicySet, Request, RequestSchemaAllPass},
    authorizer::Decision,
    entities::Entities,
    extensions::Extensions,
};

use std::{collections::HashMap, str::FromStr, sync::Arc};

use cedar_policy_core::{
    ast::{Annotations, AnyId, PolicyID},
    authorizer::{Authorizer as CedarAuthorizer, ErrorState},
};

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
        &mut self,
        request: &Request,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        let entities = self.interpreter.clone().entity_store();
        let result = self.engine.evaluate(request, &entities)?;
        self.interpreter.execute(request, result.clone())?;

        Ok(result.decision)
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    engine: CedarAuthorizer,
    policy_set: PolicySet,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub decision: Decision,
    pub satisfied_permits: Vec<String>,
    pub false_permits: Vec<String>,
    pub satisfied_forbids: Vec<String>,
    pub false_forbids: Vec<String>,
}

fn filter_ids(annotations: HashMap<PolicyID, Arc<Annotations>>) -> Vec<String> {
    let mut ids = Vec::new();
    let key = AnyId::from_str("id").expect("Can't convert 'id' key");
    for value in annotations.values() {
        match value.get(&key) {
            Some(annotation) => ids.push(annotation.val.to_string()),
            _ => {}
        }
    }
    ids
}

fn filter_false_ids(annotations: HashMap<PolicyID, (ErrorState, Arc<Annotations>)>) -> Vec<String> {
    let mut ids = Vec::new();
    let key = AnyId::from_str("id").expect("Can't convert 'id' key");
    for value in annotations.values() {
        match value.1.get(&key) {
            Some(annotation) => ids.push(annotation.val.to_string()),
            _ => {}
        }
    }
    ids
}

impl PolicyEngine {
    pub fn new(policy_set: PolicySet) -> Self {
        let engine = CedarAuthorizer::new();
        Self { engine, policy_set }
    }

    pub fn evaluate(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        let partial = self
            .engine
            .is_authorized_core(request.clone(), &self.policy_set, entities);

        let decision = partial.clone().concretize().decision;

        let satisfied_permits = filter_ids(partial.satisfied_permits);
        let false_permits = filter_false_ids(partial.false_permits);
        let satisfied_forbids = filter_ids(partial.satisfied_forbids);
        let false_forbids = filter_false_ids(partial.false_forbids);

        Ok(EvaluationResult {
            decision,
            satisfied_permits,
            false_permits,
            satisfied_forbids,
            false_forbids,
        })
    }
}
