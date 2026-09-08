use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::{Value, json};
use std::future::Future;

pub struct MockServer {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn mock_server<F, Fut>(handler: F) -> MockServer
where
    F: Fn(Value) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = (StatusCode, Json<Value>)> + Send + 'static,
{
    let app = Router::new().route("/", post(move |Json(body): Json<Value>| handler(body)));
    serve(app).await
}

pub async fn serve(app: Router) -> MockServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockServer { url, task }
}

pub fn rpc_ok(request: &Value, result: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })),
    )
}

pub fn rpc_error(request: &Value, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(
            json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32602, "message": message } }),
        ),
    )
}
