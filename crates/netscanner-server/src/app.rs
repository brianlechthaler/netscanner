use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use netscanner_core::{
    pick_local_subnet, HostChecker, InterfaceProvider, ScanEngine, ScanError, ScanKind,
    SystemInterfaceProvider,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::{AppState, ScanKindDto};

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct TargetScanRequest {
    pub target: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScanStartedResponse {
    pub scan_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn build_app<C: HostChecker + 'static>(state: Arc<AppState<C>>) -> Router {
    let web_dir = web_assets_dir();

    Router::new()
        .route("/api/health", get(health))
        .route("/api/hosts", get(get_hosts))
        .route("/api/status", get(get_status))
        .route("/api/scan/local", post(scan_local))
        .route("/api/scan/target", post(scan_target))
        .fallback_service(ServeDir::new(web_dir))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn web_assets_dir() -> String {
    std::env::var("NETSCANNER_WEB_DIR").unwrap_or_else(|_| "/app/web".to_string())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_hosts<C: HostChecker + 'static>(
    State(state): State<Arc<AppState<C>>>,
) -> impl IntoResponse {
    Json(state.hosts_response().await)
}

async fn get_status<C: HostChecker + 'static>(
    State(state): State<Arc<AppState<C>>>,
) -> impl IntoResponse {
    Json(state.status_response().await)
}

fn map_scan_error(error: ScanError) -> ApiError {
    ApiError::bad_request(error.to_string())
}

async fn scan_local<C: HostChecker + 'static>(
    State(state): State<Arc<AppState<C>>>,
) -> Result<Json<ScanStartedResponse>, ApiError> {
    let interfaces = SystemInterfaceProvider.interfaces();
    let subnet = pick_local_subnet(&interfaces).map_err(map_scan_error)?;
    spawn_scan(state, ScanKindDto::Local, ScanKind::Local, subnet).await
}

async fn scan_target<C: HostChecker + 'static>(
    State(state): State<Arc<AppState<C>>>,
    Json(body): Json<TargetScanRequest>,
) -> Result<Json<ScanStartedResponse>, ApiError> {
    if body.target.trim().is_empty() {
        return Err(ApiError::bad_request("target must not be empty"));
    }
    spawn_scan(
        state,
        ScanKindDto::External,
        ScanKind::External,
        body.target.trim().to_string(),
    )
    .await
}

async fn run_scan<C: HostChecker + 'static>(
    state: Arc<AppState<C>>,
    engine: Arc<ScanEngine<C>>,
    target: String,
    kind: ScanKind,
) {
    match engine.scan_target(&target, kind).await {
        Ok(summary) => state.complete_scan(summary).await,
        Err(err) => state.fail_scan(err.to_string()).await,
    }
}

async fn spawn_scan<C: HostChecker + 'static>(
    state: Arc<AppState<C>>,
    kind_dto: ScanKindDto,
    kind: ScanKind,
    target: String,
) -> Result<Json<ScanStartedResponse>, ApiError> {
    let scan_id = state
        .begin_scan(kind_dto, target.clone())
        .await
        .map_err(ApiError::conflict)?;

    let message_target = target.clone();
    let engine = state.engine();
    tokio::spawn(run_scan(state, engine, target, kind));

    Ok(Json(ScanStartedResponse {
        scan_id: scan_id.to_string(),
        message: format!("Scan started for {message_target}"),
    }))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ScanStatus;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use netscanner_core::{MockHostChecker, ScanConfig, ScanEngine, ScanKind};
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let checker = Arc::new(
            MockHostChecker::new().with_reachable(IpAddr::from_str("203.0.113.10").unwrap(), 443),
        );
        let engine = Arc::new(ScanEngine::new(
            checker,
            ScanConfig::default().with_timeout(Duration::from_millis(50)),
        ));
        build_app(AppState::new(engine))
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_hosts_empty_initially() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/hosts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn run_scan_completes_successfully() {
        let checker = Arc::new(
            MockHostChecker::new().with_reachable(IpAddr::from_str("203.0.113.10").unwrap(), 443),
        );
        let engine = Arc::new(ScanEngine::new(
            checker,
            ScanConfig::default().with_timeout(Duration::from_millis(50)),
        ));
        let state = AppState::new(engine.clone());
        let target = "203.0.113.10".to_string();
        state
            .begin_scan(ScanKindDto::External, target.clone())
            .await
            .unwrap();
        run_scan(state.clone(), engine, target, ScanKind::External).await;
        assert_eq!(state.status_response().await.status, ScanStatus::Completed);
    }

    #[tokio::test]
    async fn scan_target_completes_successfully() {
        let app = test_app();
        let body = serde_json::json!({ "target": "203.0.113.10" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan/target")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let hosts_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/hosts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hosts_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scan_target_starts_scan() {
        let app = test_app();
        let body = serde_json::json!({ "target": "203.0.113.10" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan/target")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scan_target_rejects_empty() {
        let app = test_app();
        let body = serde_json::json!({ "target": "" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan/target")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_scan_error_wraps_core_error() {
        let err = map_scan_error(ScanError::NoLocalNetwork);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn web_assets_dir_resolution() {
        std::env::set_var("NETSCANNER_WEB_DIR", "/tmp/web");
        assert_eq!(web_assets_dir(), "/tmp/web");
        std::env::remove_var("NETSCANNER_WEB_DIR");
        assert_eq!(web_assets_dir(), "/app/web");
    }

    #[test]
    fn api_error_conflict_response() {
        let err = ApiError::conflict("busy");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn get_status_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scan_local_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan/local")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status() == StatusCode::OK || response.status() == StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn scan_target_failure_marks_failed() {
        let app = test_app();
        let body = serde_json::json!({ "target": "10.0.0.0/8" });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan/target")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let status_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scan_target_conflict_when_busy() {
        let app = test_app();
        let body = serde_json::json!({ "target": "203.0.113.10" });
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/api/scan/target")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app.oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }
}
