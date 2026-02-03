//! Portfolio Backend - binary entry point

use portfolio_backend::run;

#[tokio::main]
async fn main() {
    run().await;
}
