use strobilus::{authorization::Authorizer, read_entities, read_obligations, read_policies, Interpreter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = read_policies("./crates/strobilus/examples/counter/policy.cedar")?;
    let entities = read_entities("./crates/strobilus/examples/counter/entities.json")?;
    let obligations = read_obligations("./crates/strobilus/examples/counter/rules.strobilus")?;

    let authorizer = Authorizer::new(policies, entities.clone());
    let mut interpreter = Interpreter::new(obligations, entities);

    println!(
        "--- Entity store BEFORE: {:?}",
        interpreter.clone().entity_store()
    );

    let request = Authorizer::request(
        r#"User::"Max""#,
        r#"Action::"read""#,
        r#"Document::"file.docx""#,
    )?;

    let decision = authorizer.is_authorized(request.clone())?;
    interpreter.execute::<()>(request, decision)?;

    println!(
        "--- Entity store AFTER: {:?}",
        interpreter.clone().entity_store()
    );

    Ok(())
}
