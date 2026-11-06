use axum::{
    Json, Router,
    body::Bytes,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};

use chrono::Local;
use serde::Deserialize;
use serde_json::Value;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

pub async fn receive_webhook(headers: HeaderMap, body: Bytes) -> Result<Json<Value>, StatusCode> {
    println!("inside receive webhook");
    let app_secret = std::env::var("WHATSAPP_APP_SECRET").expect("WHATSAPP_APP_SECRET must be set");

    // Get Meta signature
    let signature = headers
        .get("X-Hub-Signature-256")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify signature against raw request body
    if !verify_webhook_signature(&app_secret, &body, signature) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    println!("request received");
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("=======================================");
    println!("\n\nWebhook received {}\n", timestamp);

    // Only parse JSON after successful verification
    let payload: Value = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    println!("Verified webhook payload: {}", payload);

    Ok(Json(serde_json::json!({
        "status": "success"
    })))
}

fn verify_webhook_signature(app_secret: &str, raw_body: &[u8], signature: &str) -> bool {
    // Meta signature format: sha256=<hexadecimal signature>
    let Some(signature) = signature.strip_prefix("sha256=") else {
        return false;
    };

    let Ok(signature_bytes) = hex::decode(signature) else {
        return false;
    };

    let Ok(mut mac) = HmacSha256::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };

    mac.update(raw_body);

    // Constant-time signature comparison
    mac.verify_slice(&signature_bytes).is_ok()
}

pub async fn _receive_webhook(Json(payload): Json<Value>) -> StatusCode {
    println!("inside receive web hook old");
    let app_secret = std::env::var("WHATSAPP_APP_SECRET").expect("WHATSAPP_APP_SECRET must be set");
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
        .route("/", get(verify_webhook).post(receive_webhook));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
