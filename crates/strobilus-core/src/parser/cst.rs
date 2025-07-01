use cedar_policy_core::parser::cst::{Expr, Str};
use cedar_policy_core::parser::Node as CedarNode;

pub(crate) type Node<N> = CedarNode<Option<N>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // Ancora non è chiaro cosa usare per gli attributi
    AddParent(Node<Expr>, Node<Expr>),
    RemoveParent(Node<Expr>, Node<Expr>),
    //UpdateEntity(Node<Expr>, Node<Expr>, Node<Expr>, Node<Expr>),
    //RemoveEntity(Node<Expr>),
    UpdateAttribute(Node<Expr>, Node<Str>, Node<Expr>),
    RemoveAttribute(Node<Expr>, Node<Str>),

    Sequence(Box<Node<Command>>, Box<Node<Command>>),
    IfThenElse(Node<Expr>, Box<Node<Command>>, Box<Node<Command>>),
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSet {
    pub on_allow: Box<Node<Command>>,
    pub on_deny: Box<Node<Command>>,
}

impl CommandSet {
    pub fn on_allow(&self) -> Node<Command> {
        *self.on_allow.clone()
    }

    pub fn on_deny(&self) -> Node<Command> {
        *self.on_deny.clone()
    }    
}
