use strobilus_core::{executor, parser::parse_command, ast::lower_command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let args = Args::parse();

    /*
    let policy_set = read_policy(args.policy_path)?;
    let rules = read_rules(args.rules_path)?;
    println!("{:?}", rules);

    let action = args.action.parse()?;
    let principal = args.principal.parse()?;
    let resource = args.resource.parse()?;
    let request = Request::new(principal, action, resource, Context::empty(), None)?;

    let entities = read_entities(args.entities_path)?;

    // TODO: Refactor Authorizer to use cedar_policy_core crate.
    // let authorizer = authorization::Authorizer::new(policy_set, entities);
    let answer = authorizer.is_authorized_partial(&request, &policy_set, &entities);

    for policy in answer.all_residuals() {
        if answer.definitely_satisfied().any(|p| { p == policy }) {
            println!("- Policy id {}", policy.id());
            println!("-- Associate event: {:?}", policy.annotation("evt"));
        } else {
            println!("- Policy id {}", policy.id());
            println!("-- Associate event: {:?}", policy.annotation("evt"));
        }
    }

    println!("Final decision {:?}", answer.concretize().decision());
    */

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

    let mut executor = executor::Executor::with_entity_store(data)?;

    println!(
        "--- Entity store BEFORE: {:?}",
        executor.clone().entity_store()
    );

    //let command = executor::commands::update_attribute_command_1();
    let cst_command =
        parse_command(r#"updateAttribute(principal, "counter", principal.counter - 1)"#)?
            .as_inner()
            .ok_or("Failed to parse command")?
            .clone();

    let command = lower_command(cst_command);

    println!("-- Command {:?}", command);

    let _ = &executor.execute::<()>(command)?;

    let es = &executor.entity_store();
    println!("--- Entity store AFTER: {:?}", es);

    Ok(())
}
