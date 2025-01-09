use regex::Regex;
use std::collections::HashMap;

pub type EffectTable = HashMap<String, String>;

// pub struct StrobilusRule {
//     pub event: String,  // Event name of the associate rule, must be unique
//     pub action: String, // Action name of the associate rule
// }

// TODO: Use a real parser for handle grammar of Strobilus code
pub fn parse_strobilus(input: &str) -> EffectTable {
    let mut rules = EffectTable::new();
    let re = Regex::new(r"on\s+(\w+)\s+do\s+\{\s*([\s\S]*?)\s*\}").unwrap();

    if let Some(captures) = re.captures(input) {
        let event = captures[1].to_string();
        let action = captures[2].to_string();
        rules.insert(event, action);
    }

    rules
}
