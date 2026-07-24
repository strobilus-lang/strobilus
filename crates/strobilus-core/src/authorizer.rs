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
use tokio::time::*;

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
    pub fn entities(self) -> Entities {
        self.interpreter.entity_store()
    }

    pub fn is_authorized(
        &mut self,
        request: &Request,
    ) -> Result<Decision, Box<dyn std::error::Error>> {
        
        // Clone the Version Hashmap when starting transaction
        // let before = Instant::now();
        let old_versions = self.interpreter.get_versions();
        // print_task_id(&format!("Time taken to clone version hashmap: {} micros", before.elapsed().as_micros()));

        // Clone Arc containing the store and get the reference to the inner Entities
        let store_arc = self.interpreter.get_entity_store_arc();
        let entities_ref = store_arc.get_entities_ref();

        // This has to be done to ensure the code compiles, otherwise when calling execute
        // both a mutable (read_set_guard) and immutable (execute) reference to the same
        // object is taken
        let (result, read_set) = {
            // Instantiate the ReadSetGuard to clean task read set even in case of panic
            let _read_set_guard = ReadSetGuard::new(entities_ref);

            // Evaluate request on the entities
            // let before = Instant::now();
            let result = self.engine.evaluate(request, entities_ref)?;
            // print_task_id(&format!("Time taken to evaluate: {} micros", before.elapsed().as_micros()));

            // Extract read set after evaluation
            let read_set = entities_ref.extract_read_set();

            (result, read_set)
        };

        // Insert a delay before entities store is modified to force race condition
        // use std::{time::Duration, thread};
        // thread::sleep(Duration::from_millis(200));

        // Execute the obligations on the entity store
        // let before = Instant::now();
        let return_value = match self.interpreter.execute(request, result.clone(), old_versions, read_set, entities_ref) {
            Ok(()) => Ok(result.decision),
            Err(e) => Err(e)
        };
        // print_task_id(&format!("Time taken to execute: {} micros", before.elapsed().as_micros()));

        return_value
    }
}

pub struct ReadSetGuard<'a> {
    entities: &'a Entities,
    task_id: tokio::task::Id,
}

impl<'a> ReadSetGuard<'a> {
    pub fn new(entities: &'a Entities) -> Self {
        let task_id = tokio::task::id();
        entities.clean_map_entry(&task_id);
        Self {
            entities, 
            task_id
        }
    }
}

impl<'a> Drop for ReadSetGuard<'a> {
    fn drop(&mut self) {
        self.entities.clean_map_entry(&self.task_id);
    }
}

pub fn print_task_id(string: &str) {
    println!("--- TASK {:?}: {}", tokio::task::id(), string);
}