pub mod entity_store;
pub mod executor;
pub mod parser;
pub mod ast;

/* fn read_policy(filename: impl AsRef<Path>) -> Result<PolicySet, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(filename)?;
    PolicySet::from_str(&file_content).map_err(Into::into)
} */

/* fn read_entities(filename: impl AsRef<Path>) -> Result<Entities, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    Entities::from_json_file(file, None).map_err(Into::into)
} */
