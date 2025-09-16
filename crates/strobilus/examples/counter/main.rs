use strobilus::{authorization::Authorizer, read_entities, read_obligations, read_policies};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = read_policies("./crates/strobilus/examples/counter/policy.cedar")?;
    let entities = read_entities("./crates/strobilus/examples/counter/entities.json")?;
    let obligations = read_obligations("./crates/strobilus/examples/counter/rules.strobilus")?;

    let mut authorizer = Authorizer::new(policies, obligations, entities);
    
    println!(
        "--- Entity store BEFORE: {:?}",
        authorizer.clone().entities()
    );

    let request = Authorizer::request(
        r#"User::"Max""#,
        r#"Action::"read""#,
        r#"Document::"file.docx""#,
    )?;

    authorizer.is_authorized(&request)?;

    println!(
        "--- Entity store AFTER: {:?}",
        authorizer.clone().entities()
    );

    Ok(())
}
