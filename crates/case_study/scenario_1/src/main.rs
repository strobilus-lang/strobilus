use axum::{Json, Router, extract::State, routing::post, serve};

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use strobilus::{
    CommandSet, Entities, Interpreter, PolicySet, Request, authorization::Authorizer,
    parse_policyset, read_entities, read_obligations, read_policies,
};
use tokio::net::TcpListener;

use axum::http::StatusCode;

#[derive(Clone)]
struct AppState {
    policies: Arc<Mutex<PolicySet>>,
    entities: Arc<Mutex<Entities>>,
    obligations: Arc<Mutex<CommandSet>>,
    request: Arc<Mutex<Option<Request>>>,
}

#[derive(Debug, Deserialize)]
struct SetPoliciesRequest {
    policies: String,
}

#[derive(Debug, Deserialize)]
struct SetEntitiesRequest {
    entities: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    principal: String,
    action: String,
    resource: String,
    context: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    decision: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    colog::init();

    let policies = read_policies("./crates/case_study/scenario_1/src/policy.cedar")?;
    let entities = read_entities("./crates/case_study/scenario_1/src/entities.json")?;
    let obligations = read_obligations("./crates/case_study/scenario_1/src/rules.strobilus")?;

    let state = AppState {
        policies: Arc::new(Mutex::new(policies)),
        entities: Arc::new(Mutex::new(entities)),
        obligations: Arc::new(Mutex::new(obligations)),
        request: Arc::new(Mutex::new(None)),
    };

    let app = Router::new()
        .route("/authorize", post(authorize))
        .route("/policies/set", post(set_policies))
        .route("/entities/set", post(set_entities))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).await?;
    Ok(serve(listener, app).await?)
}

async fn set_policies(
    State(state): State<AppState>,
    Json(payload): Json<SetPoliciesRequest>,
) -> Result<&'static str, (StatusCode, String)> {
    let parsed = parse_policyset(&payload.policies).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to parse Cedar policies: {e}"),
        )
    })?;

    let mut policies = state.policies.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;
    *policies = parsed;

    info!("Policies set: {:?}", policies);
    Ok("Policies overwritten")
}

async fn set_entities(
    State(state): State<AppState>,
    Json(payload): Json<SetEntitiesRequest>,
) -> Result<&'static str, (StatusCode, String)> {
    todo!()
    /*     let parsed = Entities::from_json_value(payload.entities, None).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to parse Cedar entities: {e}"),
        )
    })?;

    let mut entities = state.entities.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;
    *entities = parsed;

    info!("Entities set: {:?}", entities);
    Ok("Entities overwritten") */
}

async fn authorize(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let policies = state.policies.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;

    let mut entities = state.entities.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;

    let obligations = state.obligations.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;

    let request = Authorizer::request(&payload.principal, &payload.action, &payload.resource)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request: {e}")))?;

    let mut req = state.request.lock().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lock error: {e}"),
        )
    })?;

    *req = Some(request.clone());

    let auth = Authorizer::new(policies.clone(), entities.clone());
    let decision = auth.is_authorized(request.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Authorization error: {e}"),
        )
    })?;

    info!(
        "Authorization request: principal={}, action={}, resource={}, context={:?}, decision={:?}",
        payload.principal, payload.action, payload.resource, payload.context, decision
    );

    let mut interpreter = Interpreter::new(obligations.clone(), entities.clone());
    interpreter
        .execute::<()>(request.clone(), decision.clone())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Execution error: {e}"),
            )
        })?;
    
    *entities = interpreter.entity_store().entities().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get entities: {e}"),
        )
    })?;

    info!(
        "Executed obligations for request: principal={}, action={}, resource={}, decision={:?}",
        payload.principal, payload.action, payload.resource, decision
    );

    Ok(Json(AuthResponse {
        decision: format!("{:?}", decision),
    }))
}
