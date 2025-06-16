use crate::{executor::commands::update_attribute_command_1, parser::parse_command};

pub mod entity_store;
pub mod executor;
pub mod parser;

/* fn read_policy(filename: impl AsRef<Path>) -> Result<PolicySet, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(filename)?;
    PolicySet::from_str(&file_content).map_err(Into::into)
} */

/* fn read_entities(filename: impl AsRef<Path>) -> Result<Entities, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    Entities::from_json_file(file, None).map_err(Into::into)
} */
