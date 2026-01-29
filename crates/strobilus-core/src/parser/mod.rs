//! # Parser
//! This is a collection of functions for parse a Strobilus set of commands
use std::sync::Arc;

use cedar_policy_core::parser::Node;
use lalrpop_util::lalrpop_mod;

pub mod cst;
mod err;

lalrpop_mod!(grammar);

/// Parse a single Strobilus command
pub fn parse_command(input: &str) -> Result<Node<Option<cst::Command>>, err::RawParseError<'_>> {
    let parser = grammar::CommandParser::new();
    let mut errors = Vec::new();
    parser.parse(&mut errors, &Arc::from(input), input)
}

/// Parse a set of Strobilus commands
pub fn parse_command_set(input: &str) -> Result<Node<Option<cst::CommandSet>>, err::RawParseError<'_>> {
    let parser = grammar::CommandSetParser::new();
    let mut errors = Vec::new();
    parser.parse(&mut errors, &Arc::from(input), input)
}
