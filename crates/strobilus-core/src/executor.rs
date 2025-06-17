use std::{str::FromStr, sync::Arc};
use cedar_policy_core::{ast::{EntityUID, EntityUIDEntry, Expr, Literal, Request, SlotEnv, Value, ValueKind}, evaluator::Evaluator, extensions::Extensions};

use crate::{
    ast::{command::CommandKind, Command}, entity_store::EntityStore
};

#[derive(Debug, Clone)]
pub struct Executor {
    commands: Vec<Command>,
    entity_store: EntityStore,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
            entity_store: EntityStore::new(),
        }
    }

    pub fn with_entity_store(entities: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let entity_store = EntityStore::from_entities(entities)?;
        Ok(Self {
            commands: Vec::new(),
            entity_store,
        })
    }

    pub fn entity_store(&self) -> EntityStore {
        self.entity_store.clone()
    }

    pub fn execute<T>(&mut self, command: Command<()>) -> Result<(), Box<dyn std::error::Error>> {
        match command.inner_kind() {
            CommandKind::UpdateAttribute(expr1, attribute, expr2) => {
                let (arg1, arg2): (Value, Value) =
                    match (self.clone().dummy_interpret::<()>(expr1), self.clone().dummy_interpret::<()>(expr2)) {
                        (Ok(value1), Ok(value2)) => match value1.value_kind() {
                            ValueKind::Lit(Literal::EntityUID(uid)) => {
                                //todo!("Update attribute for entity: {:?}", uid);
                                self.entity_store.update_attribute(uid, &attribute, value2.clone())?;
                                (value1, value2)
                            },
                            _ => todo!(
                                "Error when first argument of updateAttribute is not an EntityUID"
                            ),
                        },
                        (_, _) => todo!("Error when arguments of updateAttribute are not corret"),
                    };
                Ok(())
            }
        }
    }

    fn dummy_interpret<T>(self, expr: &Expr<()>) -> Result<Value, Box<dyn std::error::Error>> {
        let request = Request::new_unchecked(
            EntityUIDEntry::Known {
                euid: Arc::new(EntityUID::from_str(r#"User::"max""#)?),
                loc: None,
            },
            EntityUIDEntry::Known {
                euid: Arc::new(EntityUID::from_str(r#"Action::"view""#)?),
                loc: None,
            },
            EntityUIDEntry::Known {
                euid: Arc::new(EntityUID::from_str(r#"File::"42""#)?),
                loc: None,
            },
            None,
        );

        let entities = self.entity_store().entities()?;

        let evaluator = Evaluator::new(request, &entities, Extensions::none());

        // Convert Expr<T> to Expr<()> before interpreting
        evaluator
            .interpret(&expr, &SlotEnv::new())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
