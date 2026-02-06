//! Portfolio Backend - binary entry point
//! Delegates to the library for all app logic.

#[tokio::main]
async fn main() {
    portfolio_backend::run().await;
}
