
use std::str::FromStr;
use std::collections::HashSet;

use crate::ast::{command::CommandKind, CommandSet, Command};
pub mod validation_result;
use validation_result::{StrobilusTypeError, StrobilusTypeWarning, StrobilusValidationResult};
use smol_str::SmolStr;

use cedar_policy_core::{
    validator::ValidatorSchema, 
    validator::typecheck::SingleEnvTypechecker, 
    validator::typecheck::typecheck_answer::TypecheckAnswer, 
    validator::ValidationMode, 
    validator::types::Capability, 
    validator::types::CapabilitySet,
    validator::types::Type, 
    validator::types::EntityRecordKind, 
    validator::types::EntityLUB, 
    validator::types::RequestEnv,
    validator::types::OpenTag, 
    validator::types::Attributes,
    validator::ValidatorEntityType,
    ast::EntityType, 
    ast::ExprKind, 
    ast::PolicyID, 
};



#[derive(Debug, Clone)]
pub struct Validator {
    commands: CommandSet,
    schema: ValidatorSchema,
}

impl Validator {
    pub fn new(commands: CommandSet, schema: ValidatorSchema) -> Self {
        Self {
            commands,
            schema,
        }
    }

    pub fn validate(&mut self) -> StrobilusValidationResult {
        // Build all request environments from the schema
        let unlinked_env: Vec<RequestEnv> = self.schema
            .unlinked_request_envs(ValidationMode::Strict)
            .collect();

        let mut result = StrobilusValidationResult::new();

        // Cedar does not expose a public API for typechecking single expressions.
        // We build a "probe" template with open scope to work around this limitation
        // and gain access to the SingleEnvTypechecker.
        let policy_id = PolicyID::from_string("__typecheck_probe__");

        for request_env in &unlinked_env {
            self.typecheck_com_by_single_env(
                &*self.commands.on_allow,
                request_env,
                &CapabilitySet::new(),
                &policy_id,
                &mut result,
            );
            self.typecheck_com_by_single_env(
                &*self.commands.on_deny,
                request_env,
                &CapabilitySet::new(),
                &policy_id,
                &mut result,
            );
        }

        result
    }

    fn typecheck_com_by_single_env<'a>(
        &'a self,
        command:          &'a Command,
        request_env:      &'a RequestEnv<'a>,
        prior_capability: &CapabilitySet<'a>,
        policy_id:        &'a PolicyID,
        result:           &mut StrobilusValidationResult,
    ) -> CapabilitySet<'a> {

        let tc = Self::make_single_env_tc(&self.schema, request_env, policy_id);

        match command.inner_kind() {

            // (TypeSkip) — always valid, α' = α unchanged
            CommandKind::Skip => {
                prior_capability.clone()
            }

            // (TypeSequence)
            // α; Γ ⊢ₛ c1 : *; α1     α1; Γ ⊢ₛ c2 : *; α2
            // ─────────────────────────────────────────────
            // α; Γ ⊢ₛ c1;c2 : *; α2
            //
            // The output capabilities of c1 become the input capabilities of c2.
            CommandKind::Sequence(c1, c2) => {
                let alpha1 = self.typecheck_com_by_single_env(c1, request_env, prior_capability, policy_id, result);
                self.typecheck_com_by_single_env(c2, request_env, &alpha1, policy_id, result)
            }

            // (TypeIfC1) cond : True  → typecheck only then with α ∪ ε, skip else
            // (TypeIfC2) cond : False → typecheck only else with α, skip then
            // (TypeIfC3) cond : Bool  → typecheck both branches, α' = α1 ∩ α2
            CommandKind::IfThenElse(cond, then_cmd, else_cmd) => {

                // α; Γ ⊢ cond : Bool
                let ans_cond = Self::typecheck_expr(&tc, prior_capability, cond, Type::primitive_boolean());

                // ε = capabilities produced by the condition expression
                let epsilon = match &ans_cond {
                    TypecheckAnswer::TypecheckSuccess { expr_capability, .. } => expr_capability.clone(),
                    _ => CapabilitySet::new(),
                };

                // α ∪ ε — enriched capabilities for the then branch
                let alpha_union_epsilon = prior_capability.union(&epsilon);

                match Self::get_expr_type(&ans_cond) {

                    // TypeIfC1: α' = α1 (only then branch with α ∪ ε)
                    Some(Type::True) => {
                        result.warnings.insert(StrobilusTypeWarning::ConditionAlwaysTrue {
                            expr: cond.to_string(),
                        });
                        self.typecheck_com_by_single_env(then_cmd, request_env, &alpha_union_epsilon, policy_id, result)
                    }

                    // TypeIfC2: α' = α1 (only else branch with α)
                    Some(Type::False) => {
                        result.warnings.insert(StrobilusTypeWarning::ConditionAlwaysFalse {
                            expr: cond.to_string(),
                        });
                        self.typecheck_com_by_single_env(else_cmd, request_env, prior_capability, policy_id, result)
                    }

                    // TypeIfC3: α' = α1 ∩ α2
                    Some(_) => {
                        let alpha1 = self.typecheck_com_by_single_env(then_cmd, request_env, &alpha_union_epsilon, policy_id, result);
                        let alpha2 = self.typecheck_com_by_single_env(else_cmd, request_env, prior_capability, policy_id, result);
                        alpha1.intersect(&alpha2)
                    }

                    // Non-boolean condition — error, α' = α unchanged
                    None => {
                        result.errors.insert(StrobilusTypeError::NonBooleanCondition {
                            expr: cond.to_string(),
                        });
                        prior_capability.clone()
                    }
                }
            }

            // (TypeAddParent)
            // α; Γ ⊢ e1 : E1     α; Γ ⊢ e2 : E2     M(E1) = (_, H1)     E2 ∈ H1
            // ───────────────────────────────────────────────────────────────────────
            // α; Γ ⊢ₛ addParent(e1, e2) : *; filtp(α)
            //
            // Lean reference 
            // typeOfAddParent (uid : Expr) (parentUid : Expr) (env : TypeEnv) (α : Capabilities)
            CommandKind::AddParent(e1, e2) => {
                let ans_e1 = Self::typecheck_expr(&tc, prior_capability, e1, Type::any_entity_reference());
                let ans_e2 = Self::typecheck_expr(&tc, prior_capability, e2, Type::any_entity_reference());

                match (Self::extract_entity_type(&ans_e1), Self::extract_entity_type(&ans_e2)) {
                    (Some(E1), Some(E2)) => {
                        // M(E1) = (_, H1), check E2 ∈ H1
                        if !Self::is_valid_parent(&self.schema, E1, E2) {
                            result.errors.insert(StrobilusTypeError::InvalidParentType {
                                child_type:  E1.to_string(),
                                parent_type: E2.to_string(),
                            });
                        }
                    }
                    (None, _) => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e1.to_string(),
                        });
                    }
                    (_, None) => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e2.to_string(),
                        });
                    }
                }
                // α' = filtp(α)
                prior_capability.filtp()
            }

            // (TypeRemoveParent) — same premises as AddParent
            // α; Γ ⊢ e1 : E1     α; Γ ⊢ e2 : E2     M(E1) = (_, H1)     E2 ∈ H1
            // ───────────────────────────────────────────────────────────────────────
            // α; Γ ⊢ₛ removeParent(e1, e2) : *; filtp(α)
            //
            // Lean reference 
            // typeOfRemoveParent (uid : Expr) (parentUid : Expr) (env : TypeEnv) (α : Capabilities) 
            CommandKind::RemoveParent(e1, e2) => {
                let ans_e1 = Self::typecheck_expr(&tc, prior_capability, e1, Type::any_entity_reference());
                let ans_e2 = Self::typecheck_expr(&tc, prior_capability, e2, Type::any_entity_reference());

                match (Self::extract_entity_type(&ans_e1), Self::extract_entity_type(&ans_e2)) {
                    (Some(E1), Some(E2)) => {
                        // M(E1) = (_, H1), check E2 ∈ H1
                        if !Self::is_valid_parent(&self.schema, E1, E2) {
                            result.errors.insert(StrobilusTypeError::InvalidParentType {
                                child_type:  E1.to_string(),
                                parent_type: E2.to_string(),
                            });
                        }
                    }
                    (None, _) => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e1.to_string(),
                        });
                    }
                    (_, None) => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e2.to_string(),
                        });
                    }
                }
                // α' = filtp(α)
                prior_capability.filtp()
            }

            // (TypeRemoveEntity)
            // α; Γ ⊢ e : E
            // ─────────────────────────────────────────────
            // α; Γ ⊢ₛ removeEntity(e) : *; filtt(E, α)
            //
            // Lean reference 
            // typeOfRemoveEntity (uid : Expr) (env : TypeEnv) (α : Capabilities)
            CommandKind::RemoveEntity(e) => {
                let ans_e = Self::typecheck_expr(&tc, prior_capability, e, Type::any_entity_reference());

                match Self::extract_entity_type(&ans_e) {
                    None => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e.to_string(),
                        });
                        // α' = α unchanged on error
                        prior_capability.clone()
                    }
                    // α' = filtt(E, α)
                    Some(E) => prior_capability.filtt(E),
                }
            }

            // (TypeUpdateAttribute)
            // α; Γ ⊢ e1 : E     M(E) = ({..., ωf : τ, ...}, _)     α; Γ ⊢ e2 : τ
            // ────────────────────────────────────────────────────────────────────────
            // α; Γ ⊢ₛ updateAttribute(e1, f, e2) : *; filta(f, α ∪ {(e1, f)})
            //
            // Lean reference 
            // typeOfUpdateAttribute (uid : Expr) (attr : Attr) (newValue : Expr) (env : TypeEnv) (α : Capabilities)
            CommandKind::UpdateAttribute(e1, f, e2) => {
                let ans_e1 = Self::typecheck_expr(&tc, prior_capability, e1, Type::any_entity_reference());

                match Self::extract_entity_type(&ans_e1) {
                    None => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e1.to_string(),
                        });
                        prior_capability.clone()
                    }
                    Some(E) => {
                        // M(E) = ({..., ωf : τ, ...}, _)
                        match Self::lookup_entity(&self.schema, E).and_then(|info| info.attr(f)) {
                            None => {
                                result.errors.insert(StrobilusTypeError::UnknownAttribute {
                                    entity_type: E.to_string(),
                                    attr:        f.to_string(),
                                    expr:        e1.to_string(),
                                });
                                prior_capability.clone()
                            }
                            Some(attr_info) => {
                                // α; Γ ⊢ e2 : τ
                                let ans_e2 = Self::typecheck_expr(
                                    &tc, prior_capability, e2, attr_info.attr_type.clone(),
                                );
                                if !ans_e2.typechecked() {
                                    result.errors.insert(StrobilusTypeError::IncompatibleAttributeType {
                                        entity_type: E.to_string(),
                                        attr:        f.to_string(),
                                        value_expr:  e2.to_string(),
                                    });
                                }
                                // α' = filta(f, α ∪ {(e1, f)})
                                let new_cap = Capability::new_attribute(e1, SmolStr::new(f.as_str()));
                                prior_capability
                                    .union(&CapabilitySet::singleton(new_cap))
                                    .filta(f)
                            }
                        }
                    }
                }
            }

            // (TypeRemoveAttribute)
            // α; Γ ⊢ e : E     M(E) = ({..., ?f : τ, ...}, _)
            // ────────────────────────────────────────────────────────────────────────
            // α; Γ ⊢ₛ removeAttribute(e, f) : *; filta(f, α∖{(e', f) | e' ∈ Expr})
            //
            // Lean reference 
            // typeOfUpdateAttribute (uid : Expr) (attr : Attr) (newValue : Expr) (env : TypeEnv) (α : Capabilities)
            CommandKind::RemoveAttribute(e, f) => {
                let ans_e = Self::typecheck_expr(&tc, prior_capability, e, Type::any_entity_reference());

                match Self::extract_entity_type(&ans_e) {
                    None => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e.to_string(),
                        });
                        prior_capability.clone()
                    }
                    Some(E) => {
                        // M(E) = ({..., ?f : τ, ...}, _)
                        match Self::lookup_entity(&self.schema, E).and_then(|info| info.attr(f)) {
                            None => {
                                result.errors.insert(StrobilusTypeError::UnknownAttribute {
                                    entity_type: E.to_string(),
                                    attr:        f.to_string(),
                                    expr:        e.to_string(),
                                });
                                prior_capability.clone()
                            }
                            // f must be optional (?f) — required attributes cannot be removed
                            Some(attr_info) if attr_info.is_required => {
                                result.errors.insert(StrobilusTypeError::CannotRemoveRequiredAttribute {
                                    entity_type: E.to_string(),
                                    attr:        f.to_string(),
                                });
                                prior_capability.clone()
                            }
                            // α' = filta(f, α)
                            Some(_) => prior_capability.filta(f),
                        }
                    }
                }
            }

            // (TypeUpdateEntity)
            // α; Γ ⊢ e1 : E     α; Γ ⊢ e2 : A     M(E) = (A, H)     {E1,...,En} ⊆ H
            // ────────────────────────────────────────────────────────────────────────
            // α; Γ ⊢ₛ updateEntity(e1, e2, [E1::s1,...,En::sn]) : *; filtt(E, α)
            //
            // Lean reference 
            // typeOfUpdateEntity (uid : Expr) (attrs : Expr) (ancestors : Expr) (env : TypeEnv) (α : Capabilities)
            CommandKind::UpdateEntity(e1, e2, anc_e, tags_e) => {
                let ans_e1 = Self::typecheck_expr(&tc, prior_capability, e1, Type::any_entity_reference());

                match Self::extract_entity_type(&ans_e1) {
                    None => {
                        result.errors.insert(StrobilusTypeError::ExpectedEntity {
                            expr: e1.to_string(),
                        });
                        prior_capability.clone()
                    }
                    Some(E) => {
                        match Self::lookup_entity(&self.schema, E) {
                            None => {
                                result.errors.insert(StrobilusTypeError::UnknownEntityType {
                                    entity_type: E.to_string(),
                                    expr:        e1.to_string(),
                                });
                                prior_capability.clone()
                            }
                            Some(entity_info) => {

                                // α; Γ ⊢ e2 : A, where A is the record type of E in the schema
                                let type_A = Type::EntityOrRecord(EntityRecordKind::Record {
                                    attrs:           entity_info.attributes().clone(),
                                    open_attributes: OpenTag::ClosedAttributes,
                                });
                                let ans_e2 = Self::typecheck_expr(&tc, prior_capability, e2, type_A);
                                if !ans_e2.typechecked() {
                                    result.errors.insert(StrobilusTypeError::IncompatibleAttributeType {
                                        entity_type: E.to_string(),
                                        attr:        "(record)".to_string(),
                                        value_expr:  e2.to_string(),
                                    });
                                }

                                // {E1,...,En} ⊆ H — verify each ancestor in the list
                                if let ExprKind::Set(elements) = anc_e.expr_kind() {
                                    for element in elements.iter() {
                                        let ans_elem = Self::typecheck_expr(
                                            &tc, prior_capability, element,
                                            Type::any_entity_reference(),
                                        );
                                        match Self::extract_entity_type(&ans_elem) {
                                            None => {
                                                result.errors.insert(StrobilusTypeError::ExpectedEntity {
                                                    expr: element.to_string(),
                                                });
                                            }
                                            Some(Ei) if !Self::is_valid_parent(&self.schema, E, Ei) => {
                                                result.errors.insert(StrobilusTypeError::InvalidParentType {
                                                    child_type:  E.to_string(),
                                                    parent_type: Ei.to_string(),
                                                });
                                            }
                                            Some(_) => {}
                                        }
                                    }
                                }

                                // tags_e — open record, accepts any record including empty
                                let type_tags = Type::EntityOrRecord(EntityRecordKind::Record {
                                    attrs:           Attributes::with_required_attributes(std::iter::empty()),
                                    open_attributes: OpenTag::OpenAttributes,
                                });
                                let ans_tags = Self::typecheck_expr(&tc, prior_capability, tags_e, type_tags);
                                if !ans_tags.typechecked() {
                                    result.errors.insert(StrobilusTypeError::ExpectedEntity {
                                        expr: tags_e.to_string(),
                                    });
                                }

                                // α' = filtt(E, α)
                                prior_capability.filtt(E)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Creates a SingleEnvTypechecker for a given request environment.
    /// Corresponds to the context α; Γ in the typing rules of the paper.
    fn make_single_env_tc<'a>(
        schema: &'a ValidatorSchema,
        request_env: &'a RequestEnv<'a>,
        policy_id: &'a PolicyID,
    ) -> SingleEnvTypechecker<'a> {
        SingleEnvTypechecker::new(schema, ValidationMode::Strict, policy_id, request_env)
    }

    /// Typechecks an expression against an expected type.
    /// Corresponds to the premise α; Γ ⊢ e : τ in the typing rules of the paper.
    fn typecheck_expr<'a>(
        tc: &SingleEnvTypechecker<'a>,
        caps: &CapabilitySet<'a>,
        expr: &'a cedar_policy_core::ast::Expr,
        expected_type: Type,
    ) -> TypecheckAnswer<'a> {
        let mut type_errors = Vec::new();
        tc.expect_type(caps, expr, expected_type, &mut type_errors, |_| None)
    }

    /// Extracts the inferred type from a TypecheckAnswer.
    /// Works for both TypecheckSuccess and TypecheckFail.
    fn get_expr_type<'a>(ans: &'a TypecheckAnswer<'a>) -> Option<&'a Type> {
        match ans {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => expr_type.data().as_ref(),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => expr_recovery_type.data().as_ref(),
            TypecheckAnswer::RecursionLimit => None,
        }
    }

    /// Extracts the concrete EntityType from a TypecheckAnswer.
    /// Corresponds to the case α; Γ ⊢ e : E in the typing rules of the paper.
    fn extract_entity_type<'a>(ans: &'a TypecheckAnswer) -> Option<&'a EntityType> {
        match Self::get_expr_type(ans)? {
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                EntityLUB::get_single_entity(lub)
            }
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => Some(name),
            _ => None,
        }
    }

    /// Checks whether E2 is a valid ancestor type of E1 according to the schema.
    /// Corresponds to the check M(E1) = (_, H1) and E2 ∈ H1 in the typing rules.
    fn is_valid_parent(schema: &ValidatorSchema, E1: &EntityType, E2: &EntityType) -> bool {
        match schema.ancestors(E1) {
            Some(mut ancestors) => ancestors.any(|et| et == E2),
            None => false,
        }
    }

    /// Retrieves entity information from the schema.
    /// Corresponds to the lookup M(E) in the typing rules of the paper.
    fn lookup_entity<'a>(
        schema: &'a ValidatorSchema,
        entity_type: &EntityType,
    ) -> Option<&'a ValidatorEntityType> {
        schema.get_entity_type(entity_type)
    }Change language of a few comment and remove unnecessary code
}
