use std::fs;

use cedar_policy_core::{entities::EntityJsonParser, extensions::Extensions};

pub use cedar_policy_core::ast::PolicySet;
pub use cedar_policy_core::ast::Request;
pub use cedar_policy_core::entities::Entities;
pub use cedar_policy_core::parser::parse_policyset;

pub use strobilus_core::ast::CommandSet;
pub use strobilus_core::interpreter::Interpreter;

pub mod authorization;
mod policy_engine;

pub fn read_policies(path: &str) -> Result<PolicySet, Box<dyn std::error::Error>> {
    match fs::read_to_string(path) {
        Ok(text) => parse_policyset(&text)
            .map_err(|e| format!("Failed to parse policy set from {}: {}", path, e).into()),
        Err(_) => Ok(PolicySet::new()),
    }
}

pub fn read_entities(path: &str) -> Result<Entities, Box<dyn std::error::Error>> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let entities = EntityJsonParser::<cedar_policy_core::entities::NoEntitiesSchema>::new(
                None,
                Extensions::none(),
                cedar_policy_core::entities::TCComputation::ComputeNow,
            )
            .from_json_str(&text)?;

            Ok(entities)
        }
        Err(_) => Ok(Entities::new()),
    }
}

pub fn read_obligations(path: &str) -> Result<CommandSet, Box<dyn std::error::Error>> {
    match fs::read_to_string(path) {
        Ok(text) => strobilus_core::parse_obligations(&text)
            .map_err(|e| format!("Failed to parse obligations from {}: {}", path, e).into()),
        Err(_) => Ok(CommandSet::new()),
    }
}
