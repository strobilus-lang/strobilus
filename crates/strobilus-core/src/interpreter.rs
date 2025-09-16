use cedar_policy_core::ast::{EntityUID, PartialValue, Value};
use cedar_policy_core::entities::Entities;
use cedar_policy_core::{
    ast::{Literal, Request, SlotEnv, ValueKind},
    authorizer::Decision,
    evaluator::Evaluator,
    extensions::Extensions,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::ast::Command;
use crate::ast::{command::CommandKind, CommandSet};
use crate::entities::store::{BasicEntityStore, EntityStore};

#[derive(Debug, Clone)]
pub struct Interpreter {
    entity_store: BasicEntityStore,
    commands: Arc<CommandSet>,
}

impl Interpreter {
    pub fn new(commands: CommandSet, entities: Entities) -> Self {
        let entity_store = BasicEntityStore::new(entities);
        Self {
            entity_store,
            commands: Arc::new(commands),
        }
    }

    pub fn entity_store(self) -> Entities {
        self.entity_store.into_entities()
    }

    pub fn execute(
        &mut self,
        request: &Request,
        decision: Decision,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entities = self.entity_store.clone().into_entities();
        let evaluator = Evaluator::new(request.clone(), &entities, Extensions::none());
        let env = SlotEnv::new();

        let root_cmd = match decision {
            Decision::Allow => &*self.commands.on_allow,
            Decision::Deny => &*self.commands.on_deny,
        };

        let mut stack: Vec<&Command> = Vec::new();
        stack.push(root_cmd);

        while let Some(cmd) = stack.pop() {
            match cmd.inner_kind() {
                CommandKind::Sequence(c1, c2) => {
                    stack.push(c2);
                    stack.push(c1);
                }

                CommandKind::IfThenElse(cond, then_cmd, else_cmd) => {
                    let cond_val = evaluator.interpret(cond, &env)?;
                    match cond_val.value_kind() {
                        ValueKind::Lit(Literal::Bool(true)) => stack.push(then_cmd),
                        ValueKind::Lit(Literal::Bool(false)) => stack.push(else_cmd),
                        _ => {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Condition must evaluate to a boolean",
                            )));
                        }
                    }
                }

                CommandKind::AddParent(expr_c, expr_p) => {
                    let child_val = evaluator.interpret(expr_c, &env)?;
                    let parent_val = evaluator.interpret(expr_p, &env)?;
                    let child_uid = expect_entity_uid(child_val, "addParent")?;
                    let parent_uid = expect_entity_uid(parent_val, "addParent")?;
                    self.entity_store.add_parent(&child_uid, parent_uid);
                }

                CommandKind::RemoveParent(expr_c, expr_p) => {
                    let child_val = evaluator.interpret(expr_c, &env)?;
                    let parent_val = evaluator.interpret(expr_p, &env)?;
                    let child_uid = expect_entity_uid(child_val, "removeParent")?;
                    let parent_uid = expect_entity_uid(parent_val, "removeParent")?;
                    self.entity_store.remove_parent(&child_uid, &parent_uid);
                }

                CommandKind::UpdateEntity(uid_e, attrs_e, anc_e, tags_e) => {
                    let uid_val = evaluator.interpret(uid_e, &env)?;
                    let attrs_val = evaluator.interpret(attrs_e, &env)?;
                    let anc_val = evaluator.interpret(anc_e, &env)?;
                    let tags_val = evaluator.interpret(tags_e, &env)?;
                    let (uid, attrs, ancestors, tags) =
                        collect_update_entity_args(uid_val, attrs_val, anc_val, tags_val)?;
                    self.entity_store.update_entity(uid, attrs, ancestors, tags);
                }

                CommandKind::RemoveEntity(expr) => {
                    let v = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v, "removeEntity")?;
                    self.entity_store.remove_entity(&uid);
                }

                CommandKind::UpdateAttribute(expr, attr, value_expr) => {
                    let v1 = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v1, "updateAttribute")?;
                    let v2 = evaluator.interpret(value_expr, &env)?;
                    self.entity_store.update_attribute(&uid, attr.into(), v2);
                }

                CommandKind::RemoveAttribute(expr, attr) => {
                    let v = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v, "removeAttribute")?;
                    self.entity_store.remove_attribute(&uid, &attr.into());
                }

                CommandKind::Skip => {}
            }
        }

        Ok(())
    }
}

/// Helper to unwrap an EntityUID literal or error out
fn expect_entity_uid(val: Value, cmd_name: &str) -> Result<EntityUID, Box<dyn std::error::Error>> {
    if let ValueKind::Lit(Literal::EntityUID(uid)) = val.value_kind().clone() {
        Ok((*uid).clone())
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} requires an EntityUID", cmd_name),
        )))
    }
}

/// Helper to convert UpdateEntity args into the raw types the store expects
fn collect_update_entity_args(
    uid_val: Value,
    attrs_val: Value,
    anc_val: Value,
    tags_val: Value,
) -> Result<
    (
        EntityUID,
        BTreeMap<SmolStr, PartialValue>,
        HashSet<EntityUID>,
        BTreeMap<SmolStr, PartialValue>,
    ),
    Box<dyn std::error::Error>,
> {
    match (
        uid_val.value_kind(),
        attrs_val.value_kind(),
        anc_val.value_kind(),
        tags_val.value_kind(),
    ) {
        (
            ValueKind::Lit(Literal::EntityUID(uid)),
            ValueKind::Record(attrs),
            ValueKind::Set(ancestors),
            ValueKind::Record(tags),
        ) => Ok((
            (*uid).as_ref().clone(),
            (**attrs)
                .iter()
                .map(|(k, v)| (k.clone(), PartialValue::Value(v.clone())))
                .collect(),
            ancestors
                .authoritative
                .iter()
                .filter_map(|v| {
                    if let ValueKind::Lit(Literal::EntityUID(uid)) = v.value_kind() {
                        Some(uid.as_ref().clone())
                    } else {
                        None
                    }
                })
                .collect(),
            (**tags)
                .iter()
                .map(|(k, v)| (k.clone(), PartialValue::Value(v.clone())))
                .collect(),
        )),
        _ => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid types for updateEntity",
        ))),
    }
}
