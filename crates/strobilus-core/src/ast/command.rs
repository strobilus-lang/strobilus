use cedar_policy_core::ast::Expr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind<T = ()> {
    UpdateAttribute(Expr<T>, String, Expr<T>),
    Sequence(Box<Command<T>>, Box<Command<T>>),
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

/* /// Dummy function for generate updateAttribute command (already exisiting attribute)
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
} */
