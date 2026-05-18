use std::str::FromStr;
use strobilus::{parse_obligations_file, PolicySet, Entities, StrobilusValidator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = PolicySet::from_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/policy.cedar")?)?;
    let entities = Entities::from_json_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/entities.json")?, None)?;
    let obligations = parse_obligations_file("./crates/strobilus/examples/validator/rules.strobilus")?;
    //let schema = Schema::from_str();

    let mut val = StrobilusValidator::new(policies,obligations,entities);
    val.print();
    val.validate();

    Ok(())
}
