use cedar_policy_core::ast::Expr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind<T = ()> {
    UpdateAttribute(Expr<T>, String, Expr<T>),
    Sequence(Box<Command<T>>, Box<Command<T>>),
    IfThenElse(Expr<T>, Box<Command<T>>, Box<Command<T>>),
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
