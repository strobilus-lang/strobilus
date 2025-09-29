use strobilus::{Authorizer, read_entities, read_obligations, read_policies};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = read_policies("./crates/strobilus/examples/microservices/policy.cedar")?;
    let entities = read_entities("./crates/strobilus/examples/microservices/entities.json")?;
    let obligations = read_obligations("./crates/strobilus/examples/microservices/rules.strobilus")?;

    let mut authorizer = Authorizer::new(policies, obligations, entities);
    
    println!(
        "--- Entity store BEFORE: {:?}",
        authorizer.clone().entities()
    );

    let mut request = Authorizer::request(
        r#"Microservice::"B""#,
        r#"Action::"connect""#,
        r#"Microservice::"A""#,
    )?;

    println!("Can B talk to A?: {:?}", authorizer.is_authorized(&request)?);

    request = Authorizer::request(
        r#"Microservice::"B""#,
        r#"Action::"connect""#,
        r#"Microservice::"C""#,
    )?;

    println!("Can B talk to C?: {:?}", authorizer.is_authorized(&request)?);

    println!(
        "--- Entity store AFTER: {:?}",
        authorizer.clone().entities()
    );

   request = Authorizer::request(
        r#"Microservice::"B""#,
        r#"Action::"connect""#,
        r#"Microservice::"A""#,
    )?;

    println!("Can B talk to A again?: {:?}", authorizer.is_authorized(&request)?);

    Ok(())
}
