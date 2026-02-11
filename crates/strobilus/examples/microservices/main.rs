use std::str::FromStr;
use strobilus::{Context, Entities, PolicySet, Request, StrobilusAuthorizer, parse_obligations_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = PolicySet::from_str(&std::fs::read_to_string(
        "./crates/strobilus/examples/microservices/policy.cedar",
    )?)?;
    let entities = Entities::from_json_str(
        &std::fs::read_to_string("./crates/strobilus/examples/microservices/entities.json")?,
        None,
    )?;
    let obligations =
        parse_obligations_file("./crates/strobilus/examples/microservices/rules.strobilus")?;

    let mut authorizer = StrobilusAuthorizer::new(policies, obligations, entities);

    println!(
        "--- Entity store BEFORE: {:?}",
        authorizer.clone().entities()
    );

    let mut request = Request::new(
        r#"Microservice::"B""#.parse()?,
        r#"Action::"connect""#.parse()?,
        r#"Microservice::"A""#.parse()?,
        Context::empty(),
        None,
    )?;

    println!("Can B talk to A?: {:?}", authorizer.is_authorized(request));

    request = Request::new(
        r#"Microservice::"B""#.parse()?,
        r#"Action::"connect""#.parse()?,
        r#"Microservice::"C""#.parse()?,
        Context::empty(),
        None,
    )?;

    println!("Can B talk to C?: {:?}", authorizer.is_authorized(request));

    println!(
        "--- Entity store AFTER: {:?}",
        authorizer.clone().entities()
    );

    request = Request::new(
        r#"Microservice::"B""#.parse()?,
        r#"Action::"connect""#.parse()?,
        r#"Microservice::"A""#.parse()?,
        Context::empty(),
        None,
    )?;

    println!(
        "Can B talk to A again?: {:?}",
        authorizer.is_authorized(request)
    );

    Ok(())
}
