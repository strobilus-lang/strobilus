use cedar_policy_core::ast::{Expr, Var};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind<T = ()> {
    UpdateAttribute(Expr<T>, String, Expr<T>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command<T = ()> {
    kind: CommandKind<T>,
}

impl<T> Command<T> {
    pub fn inner_kind(&self) -> &CommandKind<T> {
        &self.kind
    }
}

impl From<crate::parser::cst::Command> for Command<()> {
    fn from(command: crate::parser::cst::Command) -> Self {
        match command {
            crate::parser::cst::Command::updateAttribute(expr1, attr, expr2) => {
                Command {
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
    
}

/// Dummy function for generate updateAttribute command (already exisiting attribute)
pub fn update_attribute_command_1() -> Command<()> {
    let principal = Expr::var(Var::Principal);

    Command {
        kind: CommandKind::UpdateAttribute(
            principal.clone(),
            "counter".into(),
            Expr::sub(Expr::get_attr(principal, "counter".into()), Expr::val(1)),
        ),
    }
}

/// Dummy function for generate updateAttribute command (already exisiting attribute)
pub fn update_attribute_command_2() -> Command<()> {
    let principal = Expr::var(Var::Principal);

    Command {
        kind: CommandKind::UpdateAttribute(
            principal.clone(),
            "role".into(),
            Expr::val("research fellow"),
        ),
    }
}
