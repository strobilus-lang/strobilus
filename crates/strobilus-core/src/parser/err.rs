use cedar_policy_core::parser::Node;
use lalrpop_util as lalr;

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<String>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;
