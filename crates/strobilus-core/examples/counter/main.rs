use cedar_policy_core::{ast::{EntityUID, EntityUIDEntry, Request}, authorizer::Decision};
use std::{str::FromStr, sync::Arc};
use strobilus_core::{
    ast::lower_command_set,
    interpreter,
    parser::parse_command_set,
};

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
    on allow {
        if (principal.counter > 0) then {
            updateAttribute(principal, "counter", principal.counter - 1)
        } else {
            updateAttribute(principal, "counter", 0)
        }
    }
    on deny { updateAttribute(principal, "counter", 0) }
    "#;

    let cst = parse_command_set(program)?;

    let ast = lower_command_set(cst)?;

    let mut interpreter = interpreter::Interpreter::with_entity_store(ast, data)?;

    println!(
        "--- Entity store BEFORE: {:?}",
        interpreter.clone().entity_store()
    );

    interpreter.execute::<()>(request, Decision::Allow)?;

    println!(
        "--- Entity store AFTER: {:?}",
        interpreter.clone().entity_store()
    );

    Ok(())
}
