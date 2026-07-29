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
use std::str::FromStr;
use std::sync::Arc;

use crate::ast::Command;
use crate::ast::{command::CommandKind, CommandSet};
use crate::authorizer::EvaluationResult;
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
        result: EvaluationResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        //
        create_justification(result.clone(), &mut self.entity_store);
        let entities = self.entity_store.clone().into_entities();
        let evaluator = Evaluator::new(request.clone(), &entities, Extensions::none());
        let env = SlotEnv::new();

        let root_cmd = match result.decision {
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

        //
        remove_jusification(&mut self.entity_store);

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

/// Helper to create special Entities "Justification::Perimt" and "Justification::Forbid"
fn create_justification(result: EvaluationResult, es: &mut BasicEntityStore) {
    let mut attributes_permits = BTreeMap::new();

    let satisfied_permits = PartialValue::from(Value::from(result.satisfied_permits));
    let false_permits = PartialValue::from(Value::from(result.false_permits));
    attributes_permits.insert(SmolStr::new("satisfied"), satisfied_permits);
    attributes_permits.insert(SmolStr::new("unsatisfied"), false_permits);

    let uid_permits = EntityUID::from_str("Justification::\"Permits\"")
        .expect("Error during creation of Justification::\"Permits\" Entity");

    es.update_entity(
        uid_permits,
        attributes_permits,
        HashSet::new(),
        BTreeMap::new(),
    );

    let mut attributes_frobids = BTreeMap::new();

    let satisfied_forbids = PartialValue::from(Value::from(result.satisfied_forbids));
    let false_forbids = PartialValue::from(Value::from(result.false_forbids));
    attributes_frobids.insert(SmolStr::new("satisfied"), satisfied_forbids);
    attributes_frobids.insert(SmolStr::new("unsatisfied"), false_forbids);

    let uid_forbids = EntityUID::from_str("Justification::\"Forbids\"")
        .expect("Error during creation of Justification::\"Forbids\" Entity");

    es.update_entity(
        uid_forbids,
        attributes_frobids,
        HashSet::new(),
        BTreeMap::new(),
    );
}

/// Helper for remove special Entities "Justification::Perimt" and "Justification::Forbid"
fn remove_jusification(es: &mut BasicEntityStore) {
    let uid_permits = EntityUID::from_str("Justification::\"Permits\"")
        .expect("Error during creation of Justification::\"Permits\" Entity");
    es.remove_entity(&uid_permits);

    let uid_forbids = EntityUID::from_str("Justification::\"Forbids\"")
        .expect("Error during creation of Justification::\"Forbids\" Entity");
    es.remove_entity(&uid_forbids);
}



// ---------------------------------- INNER INTERPRETER + VERSIONED INTERPRETER IMPLEMENTATION ----------------------------------

use imbl::HashMap;
use parking_lot::RwLock;
use crate::entities::store::OptimisticEntityStore;

// Enum to classify operations on the Entities store
pub enum StoreOp {
    AddParent {child_uid: EntityUID, parent_uid: EntityUID},
    RemoveParent {child_uid: EntityUID, parent_uid: EntityUID},
    UpdateEntity {
        uid: EntityUID,
        attrs: BTreeMap<SmolStr, PartialValue>,
        parents: HashSet<EntityUID>,
        tags: BTreeMap<SmolStr, PartialValue>
    },
    RemoveEntity {uid: EntityUID},
    UpdateAttribute {uid: EntityUID, key: SmolStr, value: Value},
    RemoveAttribute {uid: EntityUID, key: SmolStr}
}

#[derive(Debug, Clone)]
pub struct VersionHashmap {
    map: HashMap<Arc<EntityUID>, u64>,
}

impl VersionHashmap {
    pub fn new(entities: &Entities) -> Self {
        let mut map = HashMap::new();
        for e in entities.clone().into_iter() {map.insert(Arc::new(e.uid().clone()), 1);}
        Self{map}
    }

    /// For a specified uid gets the version value from shared interpreter, or 0 if value is not present
    fn get_version_value(&self, uid: &EntityUID) -> u64 {
        self.map.get(uid).copied().unwrap_or(0)
    }

    /// Extract the whole versions hashmap
    pub fn get_versions(&self) -> HashMap<Arc<EntityUID>, u64> {
        self.map.clone()
    }

    /// For a specified uid, checks that actual version and old version corresponds
    fn mismatch(&self, old_versions: &VersionHashmap, uid: &EntityUID) -> bool {
        old_versions.map.get(uid).copied().unwrap_or(0) != self.get_version_value(uid)
    }

    /// Increase version value for specified uid
    fn increase_version(&mut self, uid: &EntityUID) {
        self.map.insert(Arc::new(uid.clone()), self.get_version_value(uid) + 1);
    }

    /// Remove version value for specified uid
    fn remove_version(&mut self, uid: &EntityUID) {
        self.map.remove(uid);
    }

}

/// Struct that contains Entity store, versions hashmap and obligations
#[derive(Debug, Clone)]
pub struct VersionedInterpreter {
    entity_store: Arc<RwLock<BasicEntityStore>>,
    versions: Arc<RwLock<VersionHashmap>>,
    commands: Arc<CommandSet>,
}

impl VersionedInterpreter {
    pub fn new(commands: CommandSet, entities: Entities) -> Self {
        let versions = Arc::new(RwLock::new(VersionHashmap::new(&entities)));
        let entity_store = 
            Arc::new(
            RwLock::new(
            BasicEntityStore::new(entities)
        ));
        Self {
            entity_store,
            versions,
            commands: Arc::new(commands),
        }
    }

    /// Return the current versions map
    pub fn get_versions(&self) -> VersionHashmap {
        self.versions.read().clone()
    }

    /// Get a copy of the entities, consuming the actual store
    pub fn entity_store(self) -> Entities {
        self.get_store_clone().into_entities()
    }

    /// Clones the entities store
    /// WARNING: MIGHT BE VERY TIME CONSUMING
    pub fn get_store_clone(&self) -> BasicEntityStore {
        self.entity_store.read().clone()
    }

    /// Applies vector of StoreOp to locked entity store
    fn apply_operations(
        &self,
        entity_store: &mut BasicEntityStore,
        versions: &mut VersionHashmap, 
        op_vector: Vec<StoreOp>,
        result: EvaluationResult,
    ) {
        for operation in op_vector {
            match operation {
                StoreOp::AddParent {child_uid, parent_uid} => {
                    versions.increase_version(&child_uid);
                    entity_store.add_parent(&child_uid, parent_uid);
                },
                StoreOp::RemoveParent {child_uid, parent_uid} => {
                    versions.increase_version(&child_uid);
                    entity_store.remove_parent(&child_uid, &parent_uid);
                },
                StoreOp::UpdateEntity {uid, attrs, parents, tags} => {
                    versions.increase_version(&uid);
                    entity_store.update_entity(uid, attrs, parents, tags);
                },
                StoreOp::RemoveEntity {uid} => {
                    versions.remove_version(&uid);
                    entity_store.remove_entity(&uid);
                },
                StoreOp::UpdateAttribute {uid, key, value} => {
                    versions.increase_version(&uid);
                    entity_store.update_attribute(&uid, key, value);
                },
                StoreOp::RemoveAttribute {uid, key} => {
                    versions.increase_version(&uid);
                    entity_store.remove_attribute(&uid, &key);
                },
            };
        }
    }

    /// Validates the versions of the Entities contained in the local copy
    /// against the ones contained in the shared copy. 
    /// If there's no version mismatch apply changes to shared copy
    pub fn validate(
        &self, 
        old_versions: VersionHashmap, 
        op_vector: Vec<StoreOp>,
        write_set: HashSet<EntityUID>,
        read_set: HashSet<EntityUID>,
        result: EvaluationResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut locked_store = self.entity_store.write();
        let mut locked_versions = self.versions.write();
        let mut error_flag = false;
    
        // Check every uid in (write_set U read_set)
        for uid in read_set {
            // Check mismatch, in case signal error and break loop
            if locked_versions.mismatch(&old_versions, &uid) {
                error_flag = true;
                break;
            }
        }  

        // Check state of error_flag, if true return Error, otherwise Ok(())
        match error_flag {
            true => {
                // TODO: Should I return where the error was (what originates the mismatch) ?
                return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Mismatch during transaction validation",
                )));
            },
            false => {
                // Apply changes to shared copy
                self.apply_operations(&mut locked_store, &mut locked_versions, op_vector, result);
                Ok(())
            },
        }
    }

    /// Executes the obligations on the cloned store, returns the sequence of operations
    /// and the write set
    pub fn execute(
        &mut self,
        request: &Request,
        result: EvaluationResult,
        store_clone: &mut BasicEntityStore,
    ) -> Result<((Vec<StoreOp>, HashSet<EntityUID>)), Box<dyn std::error::Error>> {

        let mut write_set: HashSet<EntityUID> = HashSet::new();
        let mut op_vector: Vec<StoreOp> = Vec::new();
        create_justification(result.clone(), store_clone);
        
        let temp_store_clone = store_clone.clone();
        let entities_ref = temp_store_clone.get_entities_ref();
        let evaluator = Evaluator::new(request.clone(), entities_ref, Extensions::none());
        let env = SlotEnv::new();

        let root_cmd = match result.decision {
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
                    store_clone.add_parent(&child_uid, parent_uid.clone());
                    write_set.insert(child_uid.clone());
                    op_vector.push(StoreOp::AddParent{ child_uid, parent_uid });
                }

                CommandKind::RemoveParent(expr_c, expr_p) => {
                    let child_val = evaluator.interpret(expr_c, &env)?;
                    let parent_val = evaluator.interpret(expr_p, &env)?;
                    let child_uid = expect_entity_uid(child_val, "removeParent")?;
                    let parent_uid = expect_entity_uid(parent_val, "removeParent")?;
                    store_clone.remove_parent(&child_uid, &parent_uid);
                    write_set.insert(child_uid.clone());
                    op_vector.push(StoreOp::RemoveParent { child_uid, parent_uid });
                }

                CommandKind::UpdateEntity(uid_e, attrs_e, anc_e, tags_e) => {
                    let uid_val = evaluator.interpret(uid_e, &env)?;
                    let attrs_val = evaluator.interpret(attrs_e, &env)?;
                    let anc_val = evaluator.interpret(anc_e, &env)?;
                    let tags_val = evaluator.interpret(tags_e, &env)?;
                    let (uid, attrs, ancestors, tags) =
                        collect_update_entity_args(uid_val, attrs_val, anc_val, tags_val)?;
                    store_clone.update_entity(uid.clone(), attrs.clone(), ancestors.clone(), tags.clone());
                    write_set.insert(uid.clone());
                    op_vector.push(StoreOp::UpdateEntity { uid, attrs, parents: ancestors, tags });
                }

                CommandKind::RemoveEntity(expr) => {
                    let v = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v, "removeEntity")?;
                    store_clone.remove_entity(&uid);
                    write_set.insert(uid.clone());
                    op_vector.push(StoreOp::RemoveEntity { uid });
                }

                CommandKind::UpdateAttribute(expr, attr, value_expr) => {
                    let v1 = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v1, "updateAttribute")?;
                    let v2 = evaluator.interpret(value_expr, &env)?;
                    store_clone.update_attribute(&uid, attr.into(), v2.clone());
                    write_set.insert(uid.clone());
                    op_vector.push(StoreOp::UpdateAttribute { uid, key: attr.into(), value: v2 });
                }

                CommandKind::RemoveAttribute(expr, attr) => {
                    let v = evaluator.interpret(expr, &env)?;
                    let uid = expect_entity_uid(v, "removeAttribute")?;
                    store_clone.remove_attribute(&uid, &attr.into());
                    write_set.insert(uid.clone());
                    op_vector.push(StoreOp::RemoveAttribute { uid, key: attr.into() });
                }

                CommandKind::Skip => {}
            }
        }

        remove_jusification(store_clone);

        Ok((op_vector, write_set))    
    }
}