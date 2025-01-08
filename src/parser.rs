type CedarCode = String;

#[derive(Debug, Clone)]
pub struct StrobilusRule {
    pub event: String, // Event name of the associate rule, must be unique
    pub action: String, // Action name of the associate rule
}

#[derive(Debug, Clone)]
pub struct ParserResult {
    pub code: CedarCode,
    pub rules: Vec<StrobilusRule>,
}

// TODO: Use a real parser for handle grammar of Strobilus code
pub fn parse_strobilus(input: &str) -> ParserResult {
    let mut code = String::new();
    let mut rules = Vec::new();

    for line in input.lines() {
        if line.starts_with("on") {
            let mut parts = line.split_whitespace();
            let _ = parts.next(); // Skip "on"
            let event = parts.next().unwrap().to_string();
            let action: String = parts.collect::<Vec<&str>>().join(" ");
            rules.push(StrobilusRule { event, action });
        } else {
            code.push_str(line);
        }
    }

    ParserResult { code, rules }
}