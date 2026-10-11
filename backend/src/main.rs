use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "SECURE_OFFGRID_ACTIVE",
        "node": "TRV-NATIVE-LOCAL-01",
        "telemetry": "ZERO"
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/trv/status", get(health_check));
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    println!("[TRV BACKEND] Offline Daemon active on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
