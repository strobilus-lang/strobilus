use std::{str::FromStr, sync::Arc};
use cedar_policy_core::ast::{EntityUID, EntityUIDEntry, Request};
use strobilus_core::{ast::lower_command, interpreter, parser::parse_command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = r#"
        [
            {
                "uid": {
                    "type": "User",
                    "id": "max"
                },
                "attrs": {
                    "counter": 10
                },
                "parents": []
            }
        ]
    "#;

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

    let program = r#"
        updateAttribute(principal, "counter", principal.counter - 1);
        updateAttribute(principal, "counter", principal.counter - 1);
        updateAttribute(principal, "counter", principal.counter - 1)
    "#;

    let mut executor = interpreter::Interpreter::with_entity_store(data)?;

    println!(
        "--- Entity store BEFORE: {:?}",
        executor.clone().entity_store()
    );

    //let command = executor::commands::update_attribute_command_1();
    let cst_command = parse_command(program)?;

    let command = lower_command(cst_command)?;

    println!("-- Command {:?}", command);

    let _ = &executor.execute::<()>(request, command)?;

    let es = &executor.entity_store();
    println!("--- Entity store AFTER: {:?}", es);

    Ok(())
}
