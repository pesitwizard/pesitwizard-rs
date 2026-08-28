//! REST helpers shared by the binaries: error envelope, API-key check, health endpoint.

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// JSON error envelope (`{"error": "..."}`) with an HTTP status.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Message.
    pub message: String,
}

impl ApiError {
    /// 404.
    #[must_use]
    pub fn not_found(what: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: what.into(),
        }
    }

    /// 400.
    #[must_use]
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    /// 409.
    #[must_use]
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
        }
    }

    /// 500.
    #[must_use]
    pub fn internal(msg: impl ToString) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message, "message": self.message, "status": self.status.as_u16() }))).into_response()
    }
}

impl From<crate::store::StoreError> for ApiError {
    fn from(e: crate::store::StoreError) -> Self {
        Self::internal(e)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e)
    }
}

/// Health endpoint compatible with Spring Boot Actuator.
pub fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "UP", "components": { "pesit": { "status": "UP" } } }))
}

/// Middleware enforcing `X-API-Key` on `/api/**` when a key is configured.
pub async fn require_api_key(expected: Option<HeaderValue>, req: Request, next: Next) -> Response {
    let Some(expected) = expected else {
        return next.run(req).await;
    };
    if !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    let provided = req
        .headers()
        .get("x-api-key")
        .or_else(|| req.headers().get("authorization"));
    let ok = provided.is_some_and(|v| {
        v == expected
            || v.as_bytes()
                .strip_prefix(b"Bearer ")
                .is_some_and(|b| b == expected.as_bytes())
    });
    if ok {
        next.run(req).await
    } else {
        ApiError {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid or missing API key".into(),
        }
        .into_response()
    }
}

/// Resolve `${placeholders}` in a path pattern.
#[must_use]
pub fn resolve_placeholders(pattern: &str, values: &[(&str, &str)]) -> String {
    let mut out = pattern.to_owned();
    for (k, v) in values {
        out = out.replace(&format!("${{{k}}}"), v);
    }
    out
}
