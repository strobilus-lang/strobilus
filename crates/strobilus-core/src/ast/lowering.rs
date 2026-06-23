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

use cedar_policy_core::{ast::{self, ExprBuilder}, parser::cst};

use crate::{
    ast::{command::CommandKind, Command as AstCommand, CommandSet as AstCommandSet},
    parser::cst::{Command as CstCommand, CommandSet as CstCommandSet, Node},
};

trait ToAstExpr {
    fn to_ast_expr(&self) -> Result<ast::Expr, Box<dyn std::error::Error>>;
}

impl ToAstExpr for Node<cst::Expr>{
    fn to_ast_expr(&self) -> Result<ast::Expr, Box<dyn std::error::Error>> {
        Ok(self.to_expr::<ExprBuilder<()>>()?)
    }
}

fn lower_command(command: Node<CstCommand>) -> Result<AstCommand<()>, Box<dyn std::error::Error>> {
    // TODO: handle better errors
    match command.node.expect("Error parsing command") {
        CstCommand::AddParent(expr1, expr2) => Ok(AstCommand {
            kind: CommandKind::AddParent(expr1.to_ast_expr()?, expr2.to_ast_expr()?),
            loc: command.loc
        }),
        CstCommand::RemoveParent(expr1, expr2) => Ok(AstCommand {
            kind: CommandKind::RemoveParent(expr1.to_ast_expr()?, expr2.to_ast_expr()?),
            loc: command.loc
        }),
        CstCommand::UpdateEntity(uid, attributes, ancestors, tags) => {
            Ok(AstCommand {
                kind: CommandKind::UpdateEntity(
                    uid.to_ast_expr()?,
                    attributes.to_ast_expr()?,
                    ancestors.to_ast_expr()?,
                    tags.to_ast_expr()?,
                ),
                loc: command.loc
            })
        },
        CstCommand::RemoveEntity(uid) => {
            Ok(AstCommand {
                kind: CommandKind::RemoveEntity(uid.to_ast_expr()?),
                loc: command.loc
            })
        },
        CstCommand::UpdateAttribute(expr1, attr, expr2) => {
            Ok(AstCommand {
                kind: CommandKind::UpdateAttribute(
                    expr1.to_ast_expr()?,
                    // Sporcizia totale, vengono rimosse le virgolette
                    // che il parser, nonostante le regole, continua a mettere
                    {
                        let _attr = attr.node.expect("Attribute string missing").to_string();
                        _attr[1.._attr.len() - 1].to_owned()
                    },
                    //attr.to_string(),
                    expr2.to_ast_expr()?,
                ),
                loc: command.loc
            })
        }
        CstCommand::RemoveAttribute(expr1, attr) => {
            Ok(AstCommand {
                kind: CommandKind::RemoveAttribute(
                    expr1.to_ast_expr()?,
                    // Uguale a sopra
                    {
                        let _attr = attr.node.expect("Attribute string missing").to_string();
                        _attr[1.._attr.len() - 1].to_owned()
                    },
                ),
                loc: command.loc
            })
        }
        CstCommand::Sequence(c1, c2) => Ok(AstCommand {
            kind: CommandKind::Sequence(
                Box::new(lower_command(*c1)?),
                Box::new(lower_command(*c2)?),
            ),
            loc: command.loc
        }),
        CstCommand::IfThenElse(condition, c1, c2) => Ok(AstCommand {
            kind: CommandKind::IfThenElse(
                condition.to_ast_expr()?,
                Box::new(lower_command(*c1)?),
                Box::new(lower_command(*c2)?),
            ),
            loc: command.loc
        }),
        CstCommand::Skip => Ok(AstCommand {
            kind: CommandKind::Skip,
            loc: command.loc
        }),
    }
}

pub fn lower_command_set(
    command_set: Node<CstCommandSet>,
) -> Result<AstCommandSet, Box<dyn std::error::Error>> {
    // TODO: better conversion
    let on_allow = lower_command(
        command_set
            .node
            .as_ref()
            .expect("Missing command set")
            .on_allow(),
    )?;
    let on_deny = lower_command(
        command_set
            .node
            .as_ref()
            .expect("Missing command set")
            .on_deny(),
    )?;
    Ok(AstCommandSet {
        on_allow: Box::new(on_allow),
        on_deny: Box::new(on_deny),
    })
}
