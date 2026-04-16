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
