mod api;
pub use api::*;

pub use strobilus_core::ast::CommandSet;
use strobilus_core::authorizer;

/// Authorizer object, which provides responses to authorization queries
#[derive(Debug, Clone)]
pub struct StrobilusAuthorizer(authorizer::Authorizer);

impl StrobilusAuthorizer {    
    pub fn new(policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self(authorizer::Authorizer::new(policies.ast, commands, entities.0))
    }

    pub fn entities(self) -> Entities {
        Entities(self.0.entities())
    }

    pub fn is_authorized(&mut self, request: Request) -> Decision {
        match self.0.is_authorized(&request.0) {
            Ok(decision) => decision,
            Err(_) => Decision::Deny,
        }
    }
}

pub fn read_obligations(path: &str) -> Result<CommandSet, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => strobilus_core::parse_obligations(&text)
            .map_err(|e| format!("Failed to parse obligations from {}: {}", path, e).into()),
        Err(_) => Ok(CommandSet::new()),
    }
}
