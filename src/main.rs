mod entity_store;
mod executor;

/* fn read_policy(filename: impl AsRef<Path>) -> Result<PolicySet, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(filename)?;
    PolicySet::from_str(&file_content).map_err(Into::into)
} */

/* fn read_entities(filename: impl AsRef<Path>) -> Result<Entities, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    Entities::from_json_file(file, None).map_err(Into::into)
} */

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let args = Args::parse();

/*     let policy_set = read_policy(args.policy_path)?;
    let rules = read_rules(args.rules_path)?;
    println!("{:?}", rules);

    let action = args.action.parse()?;
    let principal = args.principal.parse()?;
    let resource = args.resource.parse()?;
    let request = Request::new(principal, action, resource, Context::empty(), None)?;

    let entities = read_entities(args.entities_path)?;

    println!("{:?}", entities);
    let authorizer = Authorizer::new();
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
 
    println!("Final decision {:?}", answer.concretize().decision()); */

    //let policy_set = read_policy(args.policy_path)?;
    //let rules = read_rules(args.rules_path)?;

    /* let action = args.action;
    let principal = args.principal;
    let resource = args.resource; */

    //let entities = read_entities(args.entities_path)?;

    // TODO: Refactor Authorizer to use cedar_policy_core crate.
    //let authorizer = authorization::Authorizer::new(policy_set, entities);

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

    let mut executor= executor::Executor::with_entity_store(data)?;

    println!("--- Entity store BEFORE: {:?}", executor.clone().entity_store());

    let command = executor::commands::update_attribute_command_1();
    //let command = executor::commands::update_attribute_command_2();

    let _ = &executor.execute::<()>(command)?;

    let es = &executor.entity_store();
    println!("--- Entity store AFTER: {:?}", es);

    Ok(())
}
