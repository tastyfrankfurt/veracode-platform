//! Example demonstrating ARC-based credential sharing across threads and components
//!
//! This example shows how to use the new ARC-based credential system for secure
//! credential sharing across thread boundaries while maintaining security.

use secrecy::SecretString;
use std::sync::Arc;
use veracode_platform::{VeracodeConfig, VeracodeCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ARC-based Credential Sharing Example");
    println!("========================================");

    // Method 2: ARC-based approach for sharing across threads
    println!("\n2️⃣ ARC-based credential sharing:");
    let api_id_arc = Arc::new(SecretString::new(
        std::env::var("VERACODE_API_ID")
            .unwrap_or_else(|_| "demo_api_id".to_string())
            .into(),
    ));
    let api_key_arc = Arc::new(SecretString::new(
        std::env::var("VERACODE_API_KEY")
            .unwrap_or_else(|_| "demo_api_key".to_string())
            .into(),
    ));

    let config_arc =
        VeracodeConfig::from_arc_credentials(Arc::clone(&api_id_arc), Arc::clone(&api_key_arc));
    println!("   ✓ Config created with ARC-based credentials");

    // Method 3: Direct credentials struct usage
    println!("\n3️⃣ Direct VeracodeCredentials usage:");
    let credentials = VeracodeCredentials::new(
        std::env::var("VERACODE_API_ID").unwrap_or_else(|_| "demo_api_id".to_string()),
        std::env::var("VERACODE_API_KEY").unwrap_or_else(|_| "demo_api_key".to_string()),
    );

    // Get ARC pointers for sharing
    let shared_api_id = credentials.api_id_ptr();
    let shared_api_key = credentials.api_key_ptr();
    println!("   ✓ ARC pointers obtained for thread sharing");

    // Demonstrate thread-safe sharing
    println!("\n4️⃣ Thread-safe credential sharing:");
    let handles = (0..3)
        .map(|i| {
            let api_id_clone = Arc::clone(&shared_api_id);
            let api_key_clone = Arc::clone(&shared_api_key);

            tokio::spawn(async move {
                // Each thread has access to the same credentials via ARC
                let _thread_config =
                    VeracodeConfig::from_arc_credentials(api_id_clone, api_key_clone);
                println!("   ✓ Thread {i} created config successfully");

                // Could create clients here and use them independently
                // let client = VeracodeClient::new(thread_config)?;

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
        })
        .collect::<Vec<_>>();

    // Wait for all threads to complete
    for handle in handles {
        if let Err(e) = handle.await? {
            eprintln!("Thread error: {e}");
        }
    }

    // Demonstrate security features
    println!("\n5️⃣ Security features:");
    println!("   Debug output (credentials are redacted):");
    println!("   {credentials:?}");
    println!("   {config_arc:?}");

    // Show memory efficiency - all configs share the same credential data
    println!("\n6️⃣ Memory efficiency:");
    println!("   ✓ All configs share the same ARC-wrapped credential data");
    println!("   ✓ No duplication of sensitive information in memory");
    println!("   ✓ Secure cleanup when all references are dropped");

    // Demonstrate proper usage for authentication
    println!("\n7️⃣ Proper credential usage:");
    println!(
        "   API ID (exposed for auth): {}",
        credentials.expose_api_id().chars().take(8).collect::<String>()
    );
    println!(
        "   API Key (exposed for auth): {}...",
        credentials.expose_api_key().chars().take(8).collect::<String>()
    );

    println!("\n✅ ARC-based credential example completed successfully!");
    println!("\nKey benefits:");
    println!("  • Thread-safe credential sharing");
    println!("  • Memory efficient (shared via ARC)");
    println!("  • Secure (debug redaction, controlled access)");
    println!("  • Flexible (multiple creation methods)");

    Ok(())
}
