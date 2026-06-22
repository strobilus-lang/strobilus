use std::str::FromStr;
use strobilus::{parse_obligations_file, PolicySet, Entities, StrobilusValidator};
use cedar_policy_core::{validator::ValidatorSchema, extensions::Extensions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let policies = PolicySet::from_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/policy.cedar")?)?;
    //let entities = Entities::from_json_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/entities.json")?, None)?;
    let obligations = parse_obligations_file("./crates/strobilus/examples/validator/rules.strobilus")?;
    let (schema,warnings) = ValidatorSchema::from_cedarschema_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/schema.cedarschema")?,Extensions::none())?;

    //let mut val = StrobilusValidator::new(policies,obligations,entities);
    let mut val = StrobilusValidator::new(obligations,schema);

    match val.validate() {
        Ok(result) => result.print(),
        Err(e)     => println!("Errore durante la validazione: {}", e),
    }

    Ok(())
}
