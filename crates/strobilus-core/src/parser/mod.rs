use std::sync::Arc;

use cedar_policy_core::parser::Node;
use lalrpop_util::lalrpop_mod;

pub mod cst;
mod err;

lalrpop_mod!(grammar);

pub fn parse_command(input: &str) -> Result<Node<Option<cst::Command>>, err::RawParseError> {
    let parser = grammar::CommandParser::new();
    let mut errors = Vec::new();
    parser.parse(&mut errors, &Arc::from(input), input)
}
