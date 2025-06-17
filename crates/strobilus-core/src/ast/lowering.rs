use crate::{ast::{command::CommandKind, Command as AstCommand}, parser::cst::Command as CstCommand};

pub fn lower_command(command: CstCommand) -> AstCommand<()> {
    match command {
            CstCommand::updateAttribute(expr1, attr, expr2) => {
                AstCommand {
                    kind: CommandKind::UpdateAttribute(
                        expr1.to_expr().unwrap(),
                        // Sporcizia totale, vengono rimosse le virgolette
                        // che il parser, nonostante le regole, continua a mettere
                        { 
                            let _attr =  attr.to_string();
                            _attr[1.._attr.len() - 1].to_owned()
                        },
                        //attr.to_string(),
                        expr2.to_expr().unwrap(),
                    ),
                }
            }
        }
}
