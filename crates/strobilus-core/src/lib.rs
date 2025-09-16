use crate::ast::{lower_command_set, CommandSet};

pub mod entities;
pub mod interpreter;
pub mod parser;
pub mod ast;

pub fn parse_obligations(path: &str) -> Result<CommandSet, Box<dyn std::error::Error + '_>> {
    let cst = parser::parse_command_set(path)?;
    let ast = lower_command_set(cst)?;
    Ok(ast)
}
