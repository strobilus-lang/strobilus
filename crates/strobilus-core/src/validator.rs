
use std::str::FromStr;
use std::collections::HashSet;

use crate::ast::{command::CommandKind, CommandSet, Command};


use cedar_policy_core::{
    ast::PolicySet,
    entities::Entities,
    authorizer::Decision,
    validator::ValidatorSchema,
    extensions::Extensions,
    validator::Validator as CedarValidator,
    validator::ValidationError,
    validator::ValidationWarning,
    validator::typecheck::Typechecker,
    validator::ValidationMode,
    validator::types::Capability,
    validator::types::CapabilitySet,
    ast::PolicyID,
};


#[derive(Debug, Clone)]
pub struct Validator {
    policies: PolicySet,
    commands: CommandSet,
    entities: Entities,
}

impl Validator {
    pub fn new (policies: PolicySet, commands: CommandSet, entities: Entities) -> Self {
        Self {
            policies,
            commands,
            entities,
        }
    }

    pub fn print() {
        println!("Hello 2.0");
    }

    pub fn validate(&mut self) -> Result<(), Box<dyn std::error::Error>>{
        println!("Hello From Validator"); 
        
        let (schema,warnings) = ValidatorSchema::from_cedarschema_str(&std::fs::read_to_string("./crates/strobilus/examples/validator/schema.cedarschema")?,Extensions::none())?;

        //let cedar_validato = CedarValidator::new(schema); 
        
        let mut errors : HashSet<ValidationError> = HashSet::new();
        let mut warnings : HashSet<ValidationWarning> = HashSet::new();

        let typecheck = Typechecker::new(&schema, ValidationMode::Strict);

 









        let root_cmd = &*self.commands.on_allow;

        let mut stack: Vec<&Command> = Vec::new();
        stack.push(root_cmd);

        println!("");
        println!("");
        println!("Print on allow commands");
        println!("");
        while let Some(cmd) = stack.pop() {
            match cmd.inner_kind() {
             CommandKind::Sequence(c1, c2) => {
                 println!("sequence command kind");
                 
                 stack.push(c2);
                 stack.push(c1);
             }

             CommandKind::IfThenElse(cond, then_cmd, else_cmd) => {
                println!("If then else command kind");
                println!("    {}", cond);

                stack.push(then_cmd);
                stack.push(else_cmd);
             }

             CommandKind::AddParent(expr_c, expr_p) => {println!("Add parent command kind");}

             CommandKind::RemoveParent(expr_c, expr_p) => {println!("Remove parent command kind");}

             CommandKind::UpdateEntity(uid_e, attrs_e, anc_e, tags_e) => {println!("Update entity command kind");}

             CommandKind::RemoveEntity(expr) => {println!("Remove entity command kind");}

             CommandKind::UpdateAttribute(expr, attr, value_expr) => {
                 /*schema.unlinked_request_envs(ValidationMode::Strict).collect()
                 .iter()
                 .flat_map(|unlinked_e| {
                        let single_env_typechecker = SingleEnvTypechecker {
                            schema: schema,
                            extensions: Extensions::all_available(),
                            mode: ValidationMode::Strict,
                            policy_id: PolicyID::from_string("id"),
                            request_env: &unlinked_e,
                        };
                        let check = single_env_typechecker.typecheck(CapabilitySet::new(), expr, errors);
                            (unlinked_e, check)
                     })
                     .collect();*/


                 println!("Update attribute command kind");
                 println!("    {}", expr);
                 println!("    {}", attr);
                 println!("    {}", value_expr);
             }

             CommandKind::RemoveAttribute(expr, attr) => {println!("Revmove attribute command kind");}

             CommandKind::Skip => {println!("Skip command kind");}
           }
        }

        let root_cmd = &*self.commands.on_deny;

        let mut stack: Vec<&Command> = Vec::new();
        stack.push(root_cmd);
        
        println!("");
        println!("");
        println!("Print on deny commands");
        println!("");
        while let Some(cmd) = stack.pop() {
            match cmd.inner_kind() {
             CommandKind::Sequence(c1, c2) => {
                 println!("sequence command kind");
                 stack.push(c2);
                 stack.push(c1);
             }

             CommandKind::IfThenElse(cond, then_cmd, else_cmd) => {
                println!("If then else command kind");
                println!("    {}", cond);

                stack.push(then_cmd);
                stack.push(else_cmd);
             }

             CommandKind::AddParent(expr_c, expr_p) => {println!("Add parent command kind");}

             CommandKind::RemoveParent(expr_c, expr_p) => {println!("Remove parent command kind");}

             CommandKind::UpdateEntity(uid_e, attrs_e, anc_e, tags_e) => {println!("Update entity command kind");}

             CommandKind::RemoveEntity(expr) => {println!("Remove entity command kind");}

             CommandKind::UpdateAttribute(expr, attr, value_expr) => {
                 println!("Update attribute command kind");
                 println!("    {}", expr);
                 println!("    {}", attr);
                 println!("    {}", value_expr);}

             CommandKind::RemoveAttribute(expr, attr) => {println!("Revmove attribute command kind");}

             CommandKind::Skip => {println!("Skip command kind");}
           }
        }

        Ok(())
    }

    /*fn read_schema_from_file(path: impl AsRef<Path>) -> Result<Schema> {
        let path = path.as_ref();
        let schema_src = read_from_file(path, "schema")?;
        let (schema, warnings) = Schema::from_cedarschema_str(&schema_src)
             .wrap_err_with(|| format!("failed to parse schema from file {}", path.display()))?;
        for warning in warnings {
            let report = miette::Report::new(warning);
            eprintln!("{report:?}");
        }
        Ok(schema) 
    }*/
}

