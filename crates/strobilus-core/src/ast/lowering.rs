use crate::{
    ast::{command::CommandKind, Command as AstCommand, CommandSet as AstCommandSet},
    parser::cst::{Command as CstCommand, CommandSet as CstCommandSet, Node},
};

fn lower_command(command: Node<CstCommand>) -> Result<AstCommand<()>, Box<dyn std::error::Error>> {
    // TODO: handle better errors
    match command.node.expect("Error parsing command") {
        CstCommand::UpdateAttribute(expr1, attr, expr2) => {
            Ok(AstCommand {
                kind: CommandKind::UpdateAttribute(
                    expr1.to_expr()?,
                    // Sporcizia totale, vengono rimosse le virgolette
                    // che il parser, nonostante le regole, continua a mettere
                    {
                        let _attr = attr.node.expect("Attribute string missing").to_string();
                        _attr[1.._attr.len() - 1].to_owned()
                    },
                    //attr.to_string(),
                    expr2.to_expr()?,
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
                condition.to_expr()?,
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
