use axum::{Json, Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};

use chrono::Local;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct WebhookQuery {
    #[serde(rename = "hub.mode")]
    mode: Option<String>,

    #[serde(rename = "hub.challenge")]
    challenge: Option<String>,

    #[serde(rename = "hub.verify_token")]
    verify_token: Option<String>,
}

pub async fn verify_webhook(Query(params): Query<WebhookQuery>) -> impl IntoResponse {
    let verify_token =
        std::env::var("WHATSAPP_VERIFY_TOKEN").expect("WHATSAPP_VERIFY_TOKEN must be set");

    if params.mode.as_deref() == Some("subscribe")
        && params.verify_token.as_deref() == Some(&verify_token)
    {
        println!("WEBHOOK VERIFIED");

        return (StatusCode::OK, params.challenge.unwrap_or_default());
    }

    (StatusCode::FORBIDDEN, String::new())
}

pub async fn receive_webhook(Json(payload): Json<Value>) -> StatusCode {
    println!("request received");
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("=======================================");
    println!("\n\nWebhook received {}\n", timestamp);
    println!(
        "{}\n\n\n\n",
        serde_json::to_string_pretty(&payload).unwrap()
    );
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    // build our application with a single route
    let app = Router::new()
        .route("/ping", get(|| async { "pong".to_string() }))
        .route("/", get(verify_webhook))
        .fallback(receive_webhook);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
