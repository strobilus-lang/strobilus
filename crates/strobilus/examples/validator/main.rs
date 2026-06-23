use std::str::FromStr;
use strobilus::{parse_obligations_file, PolicySet, Entities, StrobilusValidator};
use cedar_policy_core::{validator::ValidatorSchema, extensions::Extensions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let obligations = parse_obligations_file("./crates/strobilus/examples/validator/rules.strobilus")?;
    let (schema,warnings) = ValidatorSchema::from_cedarschema_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/schema.cedarschema")?,Extensions::none())?;

    let mut val = StrobilusValidator::new(obligations,schema);

    val.validate().print();  

    Ok(())
}
