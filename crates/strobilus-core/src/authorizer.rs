/*
 * Copyright 2026 Cybersecurity Lab, University of Udine or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    authorizer::Authorizer as CedarAuthorizer,
};

const STROBILUS_ID: &str = "strobilus_id";

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

fn filter_ids<T, F>(annotations: HashMap<PolicyID, T>, get_ann: F) -> Vec<String>
where
    F: Fn(&T) -> &Arc<Annotations>,
{
    let key = AnyId::from_str(STROBILUS_ID).expect("Can't convert 'id' key");
    annotations
        .values()
        .filter_map(|v| get_ann(v).get(&key))
        .map(|a| a.val.to_string())
        .collect()
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

        let satisfied_permits = filter_ids(partial.satisfied_permits, |v| v);
        let false_permits = filter_ids(partial.false_permits, |v| &v.1);
        let satisfied_forbids = filter_ids(partial.satisfied_forbids, |v| v);
        let false_forbids = filter_ids(partial.false_forbids, |v| &v.1);

        Ok(EvaluationResult {
            decision,
            satisfied_permits,
            false_permits,
            satisfied_forbids,
            false_forbids,
        })
    }
}



// ---------------------------------- OPTIMISTIC AUTHORIZER IMPLEMENTATION ----------------------------------

use crate::interpreter::VersionedInterpreter;
use crate::entities::store::OptimisticEntityStore;
use std::fmt;

#[derive(Debug, Clone)]
pub struct OptimisticAuthorizer {
    engine: Arc<PolicyEngine>,
    interpreter: VersionedInterpreter,
}

impl OptimisticAuthorizer {
    
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self {
            engine: Arc::new(PolicyEngine::new(policies)),
            interpreter: VersionedInterpreter::new(commands, entities),
        }
    }

    /// Extract entities from entities store
    /// WARNING: internally clones the store, could be very costly
    pub fn entities(self) -> Entities {
        self.interpreter.entity_store()
    }


    /// Evaluate request on the store in an optimistic way
    pub fn is_authorized(
        &mut self,
        request: &Request,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        
        // Clone the Version Hashmap when starting transaction
        let old_versions = self.interpreter.get_versions();

        // Clone the store and get the reference to the inner Entities
        let mut store_clone = self.interpreter.get_store_clone();
        let entities_ref = store_clone.get_entities_ref();

        // Evaluate request on the entities
        let result = self.engine.evaluate(request, entities_ref)?;

        // Extract the read set after evaluation
        let mut read_set = entities_ref.extract_read_set();

        // Insert a delay before entities store is modified to force race condition
        // use std::{time::Duration, thread};
        // thread::sleep(Duration::from_millis(200));

        // Execute obligations and get vector of operations, write set, and partial read set
        let (op_vector, read_set_partial) = self.interpreter.execute(request, result.clone(), &mut store_clone)?;

        // Extends the read set with the Entities accessed during obligation evaluation by the Evaluator
        read_set.extend(read_set_partial);

        // Validate + write entity_store (if no errors raise during validation)
        self.interpreter.validate(old_versions, op_vector, read_set)?;

        Ok(result.decision)
    }

    
    /// Take a write lock and executes a transaction. 
    /// Used in the worst case to prevent starvation of a single transaction.
    pub fn is_authorized_locked(
        &mut self,
        request: &Request,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        // Get locked entities store and locked version hashmap at start
        // They are kept during request execution to create the critical section
        let mut locked_store= self.interpreter.get_locked_store();
        let mut locked_versions = self.interpreter.get_locked_versions();

        // Clone the store and get the reference to the inner Entities
        let entities_ref = locked_store.get_entities_ref();

        // Evaluate request on the entities
        let result = self.engine.evaluate(request, entities_ref)?;

        // Execute obligations and get both vector of operations and write set
        let (op_vector, _read_set_partial) = self.interpreter.execute(request, result.clone(), &mut locked_store)?;

        // Apply the operations to the store
        VersionedInterpreter::apply_operations(&mut locked_store, &mut locked_versions, op_vector);

        Ok(result.decision)
    }
}


// Struct added to differentiate validation error from other types
#[derive(Debug)]
pub struct RetryableValidationError;

impl fmt::Display for RetryableValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transaction validation failed; the transaction can be retried")
    }
}

impl std::error::Error for RetryableValidationError {}