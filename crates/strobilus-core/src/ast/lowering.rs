use crate::{
    ast::{command::CommandKind, Command as AstCommand},
    parser::cst::{Command as CstCommand, Node},
};

pub fn lower_command(command: Node<CstCommand>) -> Result<AstCommand<()>, Box<dyn std::error::Error>> {
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
        CstCommand::Sequence(c1, c2) => {
            Ok(AstCommand {
                kind: CommandKind::Sequence(
                    Box::new(lower_command(*c1)?),
                    Box::new(lower_command(*c2)?),
                ),
            })
        },
    }
}
