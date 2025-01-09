use std::{fs::File, path::Path, str::FromStr};
use cedar_policy::*;
use clap::Parser;

mod parser;

/// Simple PoC of Cedar with state
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Entity of request's principal, like User::"pippo"
    #[arg(short, long)]
    principal: String,

    /// Entity of request's action, like Action::"read"
    #[arg(short, long)]
    action: String,

    /// Entity of request's resource, like Book::"1984"
    #[arg(short, long)]
    resource: String,

    /// Path of the policy
    #[arg(long, default_value = "policy.cedar")]
    policy_path: String,

    /// Path of the entites
    #[arg(long, default_value = "entities.json")]
    entities_path: String,

    // Path of the rules
    #[arg(long, default_value = "rules.strobilus")]
    rules_path: String
}

fn read_policy(filename: impl AsRef<Path>) -> Result<PolicySet, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(filename)?;
    PolicySet::from_str(&file_content).map_err(Into::into)
}

fn read_entities(filename: impl AsRef<Path>) -> Result<Entities, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    Entities::from_json_file(file, None).map_err(Into::into)
}

fn read_rules(filename: impl AsRef<Path>) -> Result<parser::EffectTable, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(filename)?;
    Ok(parser::parse_strobilus(&file_content))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let policy_set = read_policy(args.policy_path)?;
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

    println!("Final decision {:?}", answer.concretize().decision());

    Ok(())
}
