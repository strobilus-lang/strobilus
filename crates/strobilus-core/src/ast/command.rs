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
