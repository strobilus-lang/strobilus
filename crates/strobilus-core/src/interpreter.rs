use cedar_policy_core::{
    ast::{Expr, Literal, Request, SlotEnv, Value, ValueKind},
    authorizer::Decision,
    evaluator::Evaluator,
    extensions::Extensions,
};

use crate::{
    ast::{command::CommandKind, Command, CommandSet},
    entity_store::EntityStore,
};

#[derive(Debug, Clone)]
pub struct Interpreter {
    entity_store: EntityStore,
    commands: CommandSet,
}

impl Interpreter {
    pub fn new(commands: CommandSet) -> Self {
        Self {
            entity_store: EntityStore::new(),
            commands,
        }
    }

    pub fn with_entity_store(
        commands: CommandSet,
        entities: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let entity_store = EntityStore::from_entities(entities)?;
        Ok(Self {
            entity_store,
            commands,
        })
    }

    pub fn entity_store(&self) -> EntityStore {
        self.entity_store.clone()
    }

    pub fn execute<T>(
        &mut self,
        request: Request,
        decision: Decision,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let command = match decision {
            Decision::Allow => *self.commands.on_allow.clone(),
            Decision::Deny => *self.commands.on_deny.clone(),
        };
        self.recursive_execute::<T>(request, command)
    }

    fn recursive_execute<T>(
        &mut self,
        request: Request,
        command: Command,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command.inner_kind() {
            CommandKind::AddParent(expr, expr1) => {
                let child_value = self.clone().evaluate::<()>(request.clone(), expr)?;
                let parent_value = self.clone().evaluate::<()>(request.clone(), expr1)?;

                match (child_value.value_kind(), parent_value.value_kind()) {
                    (ValueKind::Lit(Literal::EntityUID(child_uid)), ValueKind::Lit(Literal::EntityUID(parent_uid))) => {
                        self.entity_store
                            .add_parent(child_uid, (**parent_uid).clone())?;
                        Ok(())
                    }
                    (ValueKind::Lit(Literal::EntityUID(_)), _) => Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Second argument of addParent must be an EntityUID",
                    ))),
                    _ => Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "First argument of addParent must be an EntityUID",
                    ))),
                }
            },
            CommandKind::RemoveParent(expr, expr1) => {
                let child_value = self.clone().evaluate::<()>(request.clone(), expr)?;
                let parent_value = self.clone().evaluate::<()>(request.clone(), expr1)?;

                match (child_value.value_kind(), parent_value.value_kind()) {
                    (ValueKind::Lit(Literal::EntityUID(child_uid)), ValueKind::Lit(Literal::EntityUID(parent_uid))) => {
                        self.entity_store
                            .remove_parent(child_uid, parent_uid)?;
                        Ok(())
                    }
                    (ValueKind::Lit(Literal::EntityUID(_)), _) => Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Second argument of removeParent must be an EntityUID",
                    ))),
                    _ => Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "First argument of removeParent must be an EntityUID",
                    ))),
                }
            },
            CommandKind::UpdateAttribute(expr1, attribute, expr2) => {
                let value1 = self.clone().evaluate::<()>(request.clone(), expr1)?;
                let value2 = self.clone().evaluate::<()>(request.clone(), expr2)?;

                if let ValueKind::Lit(Literal::EntityUID(uid)) = value1.value_kind() {
                    self.entity_store
                        .update_attribute(uid, &attribute, value2.clone())?;
                    Ok(())
                } else {
                    Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "First argument of updateAttribute must be an EntityUID",
                    )))
                }
            }
            CommandKind::RemoveAttribute(expr, attribute) => {
                let value = self.clone().evaluate::<()>(request.clone(), expr)?;

                if let ValueKind::Lit(Literal::EntityUID(uid)) = value.value_kind() {
                    self.entity_store
                        .remove_attribute(uid, attribute)?;
                    Ok(())
                } else {
                    Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Argument of removeAttribute must be an EntityUID",
                    )))
                }
            },
            CommandKind::Sequence(c1, c2) => {
                self.recursive_execute::<()>(request.clone(), c1.as_ref().clone())?;
                self.recursive_execute::<()>(request.clone(), c2.as_ref().clone())?;
                Ok(())
            }
            CommandKind::IfThenElse(condition, c1, c2) => {
                let condition_value = self.clone().evaluate::<()>(request.clone(), condition)?;
                match condition_value.value_kind() {
                    ValueKind::Lit(Literal::Bool(true)) => {
                        self.recursive_execute::<()>(request.clone(), c1.as_ref().clone())?;
                    }
                    ValueKind::Lit(Literal::Bool(false)) => {
                        self.recursive_execute::<()>(request.clone(), c2.as_ref().clone())?;
                    }
                    _ => {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Condition must evaluate to a boolean",
                        )));
                    }
                }
                Ok(())
            }
            CommandKind::Skip => Ok(()),
        }
    }

    fn evaluate<T>(
        self,
        request: Request,
        expr: &Expr<()>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let entities = self.entity_store().entities()?;
        let evaluator = Evaluator::new(request, &entities, Extensions::none());

        // Convert Expr<T> to Expr<()> before interpreting
        evaluator
            .interpret(&expr, &SlotEnv::new())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
