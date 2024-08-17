//!
//! This example showcases the Google OAuth2 process for requesting access to the Google Calendar features
//! and the user's profile.
//!
//! Before running it, you'll need to generate your own Google OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy cargo run
//! ```
//!
//! ...and follow the instructions.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Router;
use oauth2::basic::BasicClient;
use oauth2::{reqwest, EndpointNotSet, EndpointSet, PkceCodeVerifier};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use tokio::sync::oneshot;

use std::env;
use std::sync::{Arc, Mutex};

struct AppState {
    client: BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointSet>,
    csrf_state: CsrfToken,
    pkce_code_verifier: PkceCodeVerifier,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[derive(Deserialize)]
struct Auth {
    code: AuthorizationCode,
    state: CsrfToken,
}

async fn auth(State(app_state): State<Arc<AppState>>, Query(auth): Query<Auth>) -> &'static str {
    let Auth { code, state } = auth;

    println!("Google returned the following code:\n{}\n", code.secret());
    println!(
        "Google returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        app_state.csrf_state.secret()
    );

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // It is safe to leak here as we cannot move out of state.
    let pkce_code_verifier =
        PkceCodeVerifier::new(app_state.pkce_code_verifier.secret().to_owned());

    // Exchange the code with a token.
    let token_response = app_state
        .client
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(&http_client)
        .await
        .expect("Failed to exchange token");

    println!(
        "Google returned the following token:\n{:?}\n",
        token_response
    );

    // Shutdown the example app once we have done.
    let mut shutdown_tx = app_state.shutdown_tx.lock().unwrap();
    if let Some(shutdown_tx) = shutdown_tx.take() {
        shutdown_tx.send(()).unwrap();
    }

    "Go back to your terminal :)"
}

#[tokio::main]
async fn main() {
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Google OAuth2 process.
    let client = BasicClient::new(google_client_id)
        .set_client_secret(google_client_secret)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8080/auth".to_string())
                .expect("Invalid redirect URL"),
        )
        // Google supports OAuth 2.0 Token Revocation (RFC-7009)
        .set_revocation_url(
            RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
                .expect("Invalid revocation endpoint URL"),
        );

    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/calendar".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/plus.me".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    println!("Open this URL in your browser:\n{authorize_url}\n");

    // Simple state for one single oauth2 flow.
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_tx = Mutex::new(Some(shutdown_tx));
    let shared_state = Arc::new(AppState {
        client,
        csrf_state,
        pkce_code_verifier,
        shutdown_tx,
    });

    let app = Router::new()
        .route("/auth", get(auth))
        .with_state(shared_state);

    // Run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.unwrap();
        })
        .await
        .unwrap();
}
