/*
 * Copyright Cedar Contributors
 * Modified by Cybersecurity Lab, University of Udine or its affiliates. All Rights Reserved.
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

mod api;
use std::time::Duration;

pub use api::*;

pub use strobilus_core::ast::CommandSet;
use strobilus_core::authorizer;

/// Authorizer object, which provides responses to authorization queries
#[derive(Debug, Clone)]
pub struct StrobilusAuthorizer(authorizer::Authorizer);

impl StrobilusAuthorizer {
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self(authorizer::Authorizer::new(
            policies.ast,
            commands,
            entities.0,
        ))
    }

    pub fn entities(self) -> Entities {
        Entities(self.0.entities())
    }

    /// Dump an `Entities` object into an in-memory JSON object.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entities` object from JSON, use
    /// [`Self::from_json_file`], [`Self::from_json_value`], or [`Self::from_json_str`].
    pub fn to_json_value(&self) -> Result<serde_json::Value, cedar_policy_core::entities::err::EntitiesError> {
        self.0.clone().entities().to_json_value()
    }

    pub fn is_authorized(&mut self, request: Request) -> Decision {
        match self.0.is_authorized(&request.0) {
            Ok(decision) => decision,
            Err(_) => Decision::Deny,
        }
    }
}

/// Generates an empty `CommandSet`.
pub fn empty_obligations() -> CommandSet {
    CommandSet::new()
}

/// Parse a `CommandSet` from a provided string.
pub fn parse_obligations(obligations: &str) -> Result<CommandSet, Box<dyn std::error::Error>> {
    strobilus_core::parse_obligations(obligations).map_err(|e| {
        format!(
            "Failed to parse obligations from string {}: {}",
            obligations, e
        )
        .into()
    })
}

/// Parse a `CommandSet` from a path's file 
pub fn parse_obligations_file(path: &str) -> Result<CommandSet, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => strobilus_core::parse_obligations(&text)
            .map_err(|e| format!("Failed to parse obligations from {}: {}", path, e).into()),
        Err(e) => Err(Box::new(e)),
    }
}



// ---------------------------------- OPTIMISTIC WRAPPER IMPLEMENTATION ----------------------------------

use rand::{Rng, rngs::ThreadRng};
use spin_sleep;

#[derive(Clone)]
pub struct OptimisticWrapper (authorizer::OptimisticAuthorizer);

impl OptimisticWrapper {
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self(authorizer::OptimisticAuthorizer::new(
            policies.ast,
            commands,
            entities.0,
        ))
    }

    pub fn entities(self) -> Entities {
        Entities(self.0.entities())
    }

    /// Dump an `Entities` object into an in-memory JSON object.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entities` object from JSON, use
    /// [`Self::from_json_file`], [`Self::from_json_value`], or [`Self::from_json_str`].
    pub fn to_json_value(&self) -> Result<serde_json::Value, cedar_policy_core::entities::err::EntitiesError> {
        self.0.clone().entities().to_json_value()
    }

    pub fn is_authorized(&mut self, request: Request) -> Decision { 
        let mut attempt: i32 = 1;
        let max_attempt: i32 = 10;
        
        let mut return_value = Decision::Deny;
        let mut retry_flag = true;
        
        while retry_flag {
            retry_flag = false;
            return_value = match self.0.is_authorized(&request.0){
                Ok(decision) => decision, 
                Err(_) => {
                    // print_thread_id("RETRY");
                    retry_flag = true;
                    Decision::Deny
                }
            };
        }

        return_value
    }
}


// ---------------------------------- MUTEX AUTHORIZER IMPLEMENTATION ----------------------------------


use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Clone)]
pub struct PessimisticAuthorizer {
    authorizer: Arc<RwLock<StrobilusAuthorizer>>,
}

impl PessimisticAuthorizer {
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self{ 
            authorizer: Arc::new(RwLock::new(StrobilusAuthorizer::new(
                policies,
                commands,
                entities,
            )))
        }
    }

    pub fn is_authorized(&mut self, request: Request) -> Decision {
        self.authorizer.write().is_authorized(request)
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value, cedar_policy_core::entities::err::EntitiesError> {
        self.authorizer.read().to_json_value()
    }
}

pub fn print_thread_id(string: &str) {
    use std::thread::*;
    println!("--- THREAD {:?}: {}", current().id(), string);
}