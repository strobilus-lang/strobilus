use cedar_policy_core::ast::{EntityType, Expr, Name};
use smol_str::SmolStr;
use thiserror::Error;
use std::collections::HashSet;


#[derive(Debug, Error, Clone, Hash, Eq, PartialEq)]
pub enum StrobilusTypeError {

    #[error("expected an entity, but expression `{expr}` has a different type")]
    ExpectedEntity {
        expr: String,   
    },

    #[error("entity type `{entity_type}` is not declared in the schema")]
    UnknownEntityType {
        entity_type: String,
        expr:        String,
    },

    #[error("attribute `{attr}` does not exist on entity type `{entity_type}`")]
    UnknownAttribute {
        entity_type: String,
        attr:        String,
        expr:        String,
    },

    #[error("value type is not compatible with attribute `{attr}` on entity type `{entity_type}`")]
    IncompatibleAttributeType {
        entity_type: String,
        attr:        String,
        value_expr:  String,
    },

    #[error("cannot remove required attribute `{attr}` from entity type `{entity_type}`")]
    CannotRemoveRequiredAttribute {
        entity_type: String,
        attr:        String,
    },

    #[error("`{parent_type}` is not a valid parent type for `{child_type}`")]
    InvalidParentType {
        child_type:  String,
        parent_type: String,
    },

    #[error("condition in if-then-else must be boolean")]
    NonBooleanCondition {
        expr: String,
    },

    #[error("recursion limit reached while typechecking expression `{expr}`")]
    RecursionLimit {
        expr: String,
    },
}

#[derive(Debug, Error, Clone, Hash, Eq, PartialEq)]
pub enum StrobilusTypeWarning {

    #[error("condition `{expr}` is always true, else branch will never execute")]
    ConditionAlwaysTrue { expr: String },

    #[error("condition `{expr}` is always false, then branch will never execute")]
    ConditionAlwaysFalse { expr: String },
}

#[derive(Debug)]
pub struct StrobilusValidationResult {
    pub errors:   HashSet<StrobilusTypeError>,
    pub warnings: HashSet<StrobilusTypeWarning>,
}

impl StrobilusValidationResult {
    pub fn new() -> Self {
        Self {
            errors:   HashSet::new(),
            warnings: HashSet::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn print(&self) {
        if self.errors.is_empty() && self.warnings.is_empty() {
            println!("✓ Validazione completata senza errori");
            return;
        }

        if !self.errors.is_empty() {
            println!("Errors ({})", self.errors.len());
            for error in &self.errors {
                println!("     {}", error);
            }
        }

        if !self.warnings.is_empty() {
            println!("Warning ({})", self.warnings.len());
            for warning in &self.warnings {
                println!("     {}", warning);
            }
        }
    }
}
