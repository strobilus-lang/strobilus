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
        }),
        CstCommand::RemoveParent(expr1, expr2) => Ok(AstCommand {
            kind: CommandKind::RemoveParent(expr1.to_ast_expr()?, expr2.to_ast_expr()?),
        }),
        CstCommand::UpdateEntity(uid, attributes, ancestors, tags) => {
            Ok(AstCommand {
                kind: CommandKind::UpdateEntity(
                    uid.to_ast_expr()?,
                    attributes.to_ast_expr()?,
                    ancestors.to_ast_expr()?,
                    tags.to_ast_expr()?,
                ),
            })
        },
        CstCommand::RemoveEntity(uid) => {
            Ok(AstCommand {
                kind: CommandKind::RemoveEntity(uid.to_ast_expr()?),
            })
        },
        CstCommand::UpdateAttribute(expr1, attr, expr2) => {
            Ok(AstCommand {
                kind: CommandKind::UpdateAttribute(
                    expr1.to_ast_expr()?,
                    {
                        let _attr = attr.node.expect("Attribute string missing").to_string();
                        _attr[1.._attr.len() - 1].to_owned()
                    },
                    expr2.to_ast_expr()?,
                ),
            })
        }
        CstCommand::RemoveAttribute(expr1, attr) => {
            Ok(AstCommand {
                kind: CommandKind::RemoveAttribute(
                    expr1.to_ast_expr()?,
                    {
                        let _attr = attr.node.expect("Attribute string missing").to_string();
                        _attr[1.._attr.len() - 1].to_owned()
                    },
                ),
            })
        }
        CstCommand::Sequence(c1, c2) => Ok(AstCommand {
            kind: CommandKind::Sequence(
                Box::new(lower_command(*c1)?),
                Box::new(lower_command(*c2)?),
            ),
        }),
        CstCommand::IfThenElse(condition, c1, c2) => Ok(AstCommand {
            kind: CommandKind::IfThenElse(
                condition.to_ast_expr()?,
                Box::new(lower_command(*c1)?),
                Box::new(lower_command(*c2)?),
            ),
        }),
        CstCommand::Skip => Ok(AstCommand {
            kind: CommandKind::Skip,
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
