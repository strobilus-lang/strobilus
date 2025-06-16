use cedar_policy_core::parser::cst::{Expr, Str};
use cedar_policy_core::parser::Node as CedarNode;

type Node<N> = CedarNode<Option<N>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // Ancora non è chiaro cosa usare per gli attributi
    updateAttribute(Node<Expr>, Str, Node<Expr>),
}
