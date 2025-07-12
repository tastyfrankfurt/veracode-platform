use crate::cli::Args;

pub fn validate_api_credential(value: &str, field_name: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} cannot be empty", field_name));
    }
    
    if !value.chars().all(|c| c.is_alphanumeric()) {
        return Err(format!("{} must contain only alphanumeric characters", field_name));
    }
    
    Ok(())
}

pub fn load_api_credentials(args: &mut Args) -> Result<(), i32> {
    args.api_id = match std::env::var("VERACODE_API_ID") {
        Ok(id) => {
            if let Err(e) = validate_api_credential(&id, "VERACODE_API_ID") {
                eprintln!("❌ Invalid VERACODE_API_ID: {}", e);
                return Err(1);
            }
            Some(id)
        }
        Err(_) => None,
    };
    
    args.api_key = match std::env::var("VERACODE_API_KEY") {
        Ok(key) => {
            if let Err(e) = validate_api_credential(&key, "VERACODE_API_KEY") {
                eprintln!("❌ Invalid VERACODE_API_KEY: {}", e);
                return Err(1);
            }
            Some(key)
        }
        Err(_) => None,
    };
    
    Ok(())
}

pub fn check_pipeline_credentials(args: &Args) -> Result<(String, String), ()> {
    match (&args.api_id, &args.api_key) {
        (Some(id), Some(key)) => Ok((id.clone(), key.clone())),
        _ => {
            eprintln!("❌ Pipeline scan requires Veracode API credentials");
            eprintln!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
            eprintln!("💡 API credentials must contain only alphanumeric characters");
            Err(())
        }
    }
}