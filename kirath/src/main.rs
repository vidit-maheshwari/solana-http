use axum::{routing::post, Router};
use std::net::SocketAddr;
use axum::{Json, response::{IntoResponse, Response}};
use serde::{Serialize, Deserialize};
use solana_sdk::program_error::ProgramError;

// --- API Response Types ---

pub type ApiResult<T> = Result<Json<ApiResponse<T>>, ApiError>;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }
    pub fn error(msg: String) -> Self {
        Self { success: false, data: None, error: Some(msg) }
    }
}

#[derive(Debug)]
pub enum ApiError {
    InvalidInput(String),
    MissingFields,
    Other(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let msg = match &self {
            ApiError::InvalidInput(m) => m.clone(),
            ApiError::MissingFields => "Missing required fields".to_string(),
            ApiError::Other(m) => m.clone(),
        };
        let body = Json(ApiResponse::<()> { success: false, data: None, error: Some(msg) });
        (axum::http::StatusCode::BAD_REQUEST, body).into_response()
    }
}

impl From<ProgramError> for ApiError {
    fn from(e: ProgramError) -> Self {
        ApiError::Other(format!("Solana ProgramError: {}", e))
    }
}

mod solana_handlers;
use solana_handlers::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
} 