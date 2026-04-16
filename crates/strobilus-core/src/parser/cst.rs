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

//! # Concrete Syntax Tree 
//! It's the first representation of Strobilus program
use cedar_policy_core::parser::cst::{Expr, Str};
use cedar_policy_core::parser::Node as CedarNode;

pub(crate) type Node<N> = CedarNode<Option<N>>;

/// These are the possible forms of Strobilus commands
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // Basic commands
    AddParent(Node<Expr>, Node<Expr>),
    RemoveParent(Node<Expr>, Node<Expr>),
    UpdateEntity(Node<Expr>, Node<Expr>, Node<Expr>, Node<Expr>),
    RemoveEntity(Node<Expr>),
    UpdateAttribute(Node<Expr>, Node<Str>, Node<Expr>),
    RemoveAttribute(Node<Expr>, Node<Str>),
    // Commands
    Sequence(Box<Node<Command>>, Box<Node<Command>>),
    IfThenElse(Node<Expr>, Box<Node<Command>>, Box<Node<Command>>),
    Skip,
}

/// This structure represents the entrypoint of
/// Strobilus programs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSet {
    pub on_allow: Box<Node<Command>>,
    pub on_deny: Box<Node<Command>>,
}

impl CommandSet {
    /// Returns the commands for ALLOW decisions
    pub fn on_allow(&self) -> Node<Command> {
        *self.on_allow.clone()
    }

    /// Returns the commands for DENY decisions
    pub fn on_deny(&self) -> Node<Command> {
        *self.on_deny.clone()
    }    
}
