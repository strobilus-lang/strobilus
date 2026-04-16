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

use cedar_policy_core::parser::Node;
use lalrpop_util as lalr;

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<String>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;
