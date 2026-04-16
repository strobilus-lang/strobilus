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

use cedar_policy_core::ast::Expr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind<T = ()> {
    AddParent(Expr<T>, Expr<T>),
    RemoveParent(Expr<T>, Expr<T>),
    UpdateEntity(Expr<T>, Expr<T>, Expr<T>, Expr<T>),
    RemoveEntity(Expr<T>),
    UpdateAttribute(Expr<T>, String, Expr<T>),
    RemoveAttribute(Expr<T>, String),
    Sequence(Box<Command<T>>, Box<Command<T>>),
    IfThenElse(Expr<T>, Box<Command<T>>, Box<Command<T>>),
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command<T = ()> {
    pub kind: CommandKind<T>,
}

impl<T> Command<T> {
    pub fn inner_kind(&self) -> &CommandKind<T> {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSet<T = ()> {
    pub on_allow: Box<Command<T>>,
    pub on_deny: Box<Command<T>>,
}

impl<T> CommandSet<T> {
    pub fn new() -> Self {
        Self {
            on_allow: Box::new(Command { kind: CommandKind::Skip }),
            on_deny: Box::new(Command { kind: CommandKind::Skip }),
        }
    }
}
