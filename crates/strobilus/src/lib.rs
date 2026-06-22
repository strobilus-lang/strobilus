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
pub use api::*;

pub use strobilus_core::ast::CommandSet;
use strobilus_core::authorizer;
use strobilus_core::validator;
pub use validator::validation_result::StrobilusValidationResult;
use cedar_policy_core::validator::ValidatorSchema;

/// Validator object, which provides responses to validator queries
#[derive(Debug, Clone)]
pub struct StrobilusValidator(validator::Validator);

impl StrobilusValidator {
    pub fn new(commands: CommandSet, schema: ValidatorSchema) -> Self {
        Self(validator::Validator::new(
            commands,
            schema,
        ))    
    }


    pub fn validate(&mut self) -> Result<StrobilusValidationResult, Box<dyn std::error::Error>> {
        self.0.validate()
    }
}

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
