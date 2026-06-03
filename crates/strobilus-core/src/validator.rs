
use std::str::FromStr;
use std::collections::HashSet;

use crate::ast::{command::CommandKind, CommandSet, Command};


use cedar_policy_core::{
    ast::PolicySet,
    ast::Template,
    //ast::Type,
    entities::Entities,
    authorizer::Decision,
    validator::ValidatorSchema,
    extensions::Extensions, 
    validator::Validator as CedarValidator,
    validator::ValidationError,
    validator::ValidationWarning,
    validator::typecheck::SingleEnvTypechecker,
    validator::typecheck::Typechecker,
    validator::typecheck::typecheck_answer::TypecheckAnswer,
    validator::ValidationMode,
    validator::types::Capability,
    validator::types::CapabilitySet,
    validator::typecheck::PolicyCheck,
    validator::types::Type,
    validator::types::RequestEnv,
    ast::PolicyID,
    ast::ResourceConstraint,
    ast::ActionConstraint,
    ast::PrincipalConstraint,
    ast::Effect,
    ast::Annotations,
    ast::Expr,
    ast::ExprBuilder,
    expr_builder::ExprBuilder as _,
};



#[derive(Debug, Clone)]
pub struct Validator {
    commands: CommandSet,
    schema: ValidatorSchema,
}

impl Validator {
    pub fn new (commands: CommandSet, schema: ValidatorSchema) -> Self {
        Self {
            commands,
            schema,
        }
    }

    pub fn validate(&mut self) -> Result<(), Box<dyn std::error::Error>>{
        
        // Unlinked request enviramets
        let unlinked_env: Vec<RequestEnv> = self.schema.unlinked_request_envs(ValidationMode::Strict).collect(); 


        // Typechecker
        let mut errors : HashSet<ValidationError> = HashSet::new();
        let mut warnings : HashSet<ValidationWarning> = HashSet::new();

        let typecheck = Typechecker::new(&self.schema, ValidationMode::Strict); 
        
        for request_env in &unlinked_env {

            println!("Validate on allow commands");
            self.typecheck_com_by_single_env(&*self.commands.on_allow, &request_env, &CapabilitySet::new(),&typecheck);


            println!("Validate on deny commands");
            self.typecheck_com_by_single_env(&*self.commands.on_deny, &request_env, &CapabilitySet::new(),&typecheck);
        }


        
        Ok(())
    }

    fn typecheck_com_by_single_env(&self, command: &Command, request_env: &RequestEnv, prior_capability: &CapabilitySet, typecheck: &Typechecker) {        
        match command.inner_kind() {
             CommandKind::Sequence(c1, c2) => {
                 println!("    sequence command kind");
                
                 self.typecheck_com_by_single_env(c2, &request_env, prior_capability, &typecheck);
                 self.typecheck_com_by_single_env(c1, &request_env, prior_capability, &typecheck);
             }

             CommandKind::IfThenElse(cond, then_cmd, else_cmd) => {
                println!("    If then else command kind");
                println!("        {}", cond);
                
                self.typecheck_com_by_single_env(then_cmd, &request_env, prior_capability, &typecheck);
                self.typecheck_com_by_single_env(else_cmd, &request_env, prior_capability, &typecheck);
             }

             CommandKind::AddParent(expr_c, expr_p) => {println!("    Add parent command kind");}

             CommandKind::RemoveParent(expr_c, expr_p) => {println!("    Remove parent command kind");}

             CommandKind::UpdateEntity(uid_e, attrs_e, anc_e, tags_e) => {println!("    Update entity command kind");}

             CommandKind::RemoveEntity(expr) => {println!("    Remove entity command kind");}

             CommandKind::UpdateAttribute(expr, attr, value_expr) => {
                println!("    Update attribute command kind : UpdateAttribute( expr, attr, value_expr)");
            
                // Single evn typechecker
                let mut type_errors = Vec::new();
                let policy_id = PolicyID::from_string("__typecheck_probe__");
                let single_env_typechecker = SingleEnvTypechecker::new(&self.schema, ValidationMode::Strict, &policy_id, request_env); 
 
                let ans = single_env_typechecker.expect_type(
                    &prior_capability,
                    expr,
                    Type::any_entity_reference(),
                    &mut type_errors,
                    |_| None,
                );

                print!("        Typechecking entity...");
                match ans.typechecked() {
                    true => println!("Success"),
                    false => println!("Fail"),
                }

                ans.then_typecheck(|typ, cap| 
                    match typ.data() {
                        Some(typ_actual) => {
                            println!("        Entity Success");
                            //let all_attrs = typ_actual.all_attributes(&self.schema);
                            let attr_ty = Type::lookup_attribute_type(&self.schema, typ_actual, attr);
                            /*let annot_expr = ExprBuilder::with_data(
                                attr_ty
                                    .as_ref()
                                    .map(|attr_ty| attr_ty.attr_type.as_ref().clone()),
                            )
                            .with_same_source_loc(expr)
                            .get_attr(typ_expr_actual.clone(), attr.clone());*/
                            match attr_ty {
                                Some(ty) => {
                                    println!("        Attribute Success");
                                    TypecheckAnswer::success(
                                        ExprBuilder::with_data(Some(Type::Never))
                                            .with_same_source_loc(expr)
                                            .get_attr(typ, attr.clone().into()),
                                    )
                                }
                                None => {
                                    println!("        Attribute Faild");
                                    TypecheckAnswer::fail(
                                        ExprBuilder::new()
                                            .with_same_source_loc(expr)
                                            .get_attr(typ, attr.clone().into()),
                                    )
                                }
                            }
                        }
                        None => {
                            println!("        Entity Faild");
                            TypecheckAnswer::fail(
                                ExprBuilder::new()
                                    .with_same_source_loc(expr)
                                    .get_attr(typ, attr.clone().into()),
                            )
                        }
                    });
    
                        


                /*let e1_types = self.infer_expr_type(&typecheck, expr);

                println!("        (expr) \"{}\" : (env,type)",expr);
                for (i, tipo) in e1_types.iter().enumerate() {
                    match tipo {
                        Some(t) => println!("           ({},{})", i, t),
                        None    => println!("           ({},tipo non inferito)", i),
                   }
                }
                println!("");*/

                
                println!("       {}", attr);
                println!("");

                let e2_types = self.infer_expr_type(&typecheck, value_expr);

                println!("        (expr) \"{}\" : (env,type)",value_expr);
                for (i, tipo) in e2_types.iter().enumerate() {
                   match tipo {
                        Some(t) => println!("           ({},{})", i, t),
                        None    => println!("           ({},tipo non inferito)", i),
                   }
                }
                println!("");
             }

             CommandKind::RemoveAttribute(expr, attr) => {println!("    Revmove attribute command kind");}

             CommandKind::Skip => {println!("    Skip command kind");}
           }
        }

    fn infer_expr_type(
        &self,
        typecheck: &Typechecker,
        expr: &Expr,
    ) -> Vec<Option<Type>> {
        // Costruisci il template probe
        let template = Template::new(
            PolicyID::from_string("__typecheck_probe__"),
            None,
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            expr.clone(),
        );

        // Typecheck su tutti gli environment
        typecheck
            .typecheck_by_request_env(&template)
            .into_iter()
            .map(|(_, check)| match check {
                // Caso SUCCESS — il tipo è dentro l'expr annotata
                PolicyCheck::Success(typed_expr) => {
                    // typed_expr è Expr<Option<Type>>
                    // .data() legge l'annotazione sul nodo radice
                    typed_expr.data().clone()
                }
                // Caso IRRELEVANT — Cedar ha determinato che la policy
                // è sempre False in questo env (tipo False)
                PolicyCheck::Irrelevant(_, _) => {
                    Some(Type::singleton_boolean(false))
                }
                // Caso FAIL — errore di tipo, proviamo a recuperare
                // il tipo reale dagli errori UnexpectedType
                PolicyCheck::Fail(errors) => {
                    errors.iter().find_map(|e| {
                        if let ValidationError::UnexpectedType(u) = e {
                            Some(u.actual.clone())
                        } else {
                            None
                        }
                    })
                }
            })
            .collect()
    }

    /*fn infer_expr_type2(
        &self,
        typecheck: &Typechecker,
        expr: &Expr,
    ) -> Vec<Option<Type>> {
        let template = Template::new(
            PolicyID::from_string("__typecheck_probe__"),
            None,
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            expr.clone(),
        );

        typecheck
            .typecheck_by_request_env(&template)
            .into_iter()
            .map(|(_, check)| match check {
                // Entrambi i casi hanno l'Expr annotata — .data() legge il tipo del nodo radice
                PolicyCheck::Success(typed_expr)        => typed_expr.data().clone(),
                PolicyCheck::Irrelevant(_, typed_expr)  => typed_expr.data().clone(),
                // Fail non ha l'Expr annotata — il typecheck non è arrivato a produrla
                PolicyCheck::Fail(_)                    => None,
            })
            .collect()
    }*/
}

