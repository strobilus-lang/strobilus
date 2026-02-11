use std::str::FromStr;
use strobilus::{parse_obligations_file, Context, Entities, PolicySet, Request, StrobilusAuthorizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = PolicySet::from_str(&std::fs::read_to_string("./crates/strobilus/examples/counter/policy.cedar")?)?;
    let entities = Entities::from_json_str(&std::fs::read_to_string("./crates/strobilus/examples/counter/entities.json")?, None)?;
    let obligations = parse_obligations_file("./crates/strobilus/examples/counter/rules.strobilus")?;

    let mut authorizer = StrobilusAuthorizer::new(policies, obligations, entities);
    
    println!(
        "--- Entity store BEFORE: {:?}",
        authorizer.clone().entities()
    );

    let request = Request::new(
        r#"User::"Max""#.parse()?,
        r#"Action::"read""#.parse()?,
        r#"Document::"file.docx""#.parse()?,
        Context::empty(),
        None
    )?;

    authorizer.is_authorized(request);

    println!(
        "--- Entity store AFTER: {:?}",
        authorizer.clone().entities()
    );

    Ok(())
}
