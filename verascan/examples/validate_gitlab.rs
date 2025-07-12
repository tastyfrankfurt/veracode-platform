#!/usr/bin/env rust-script

//! GitLab Connectivity Validation Example
//! 
//! This example validates GitLab integration requirements and connectivity
//! without running a full pipeline scan.
//! 
//! Usage:
//! 1. Set environment variables (PRIVATE_TOKEN, CI_PROJECT_ID, etc.)
//! 2. Run: cargo run --example validate_gitlab

use std::env;
use verascan::gitlab_issues::GitLabIssuesClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 GitLab Integration Validation");
    println!("================================");
    
    // Check if environment variables are set
    println!("🔍 Checking environment variables...");
    
    let token_vars = ["PRIVATE_TOKEN", "CI_TOKEN", "GITLAB_TOKEN"];
    let token_found = token_vars.iter().any(|var| env::var(var).is_ok());
    
    if !token_found {
        println!("❌ No GitLab token found!");
        println!("   Please set one of: PRIVATE_TOKEN, CI_TOKEN, or GITLAB_TOKEN");
        return Ok(());
    }
    
    if env::var("CI_PROJECT_ID").is_err() {
        println!("❌ CI_PROJECT_ID not set!");
        println!("   Please set CI_PROJECT_ID to your GitLab project ID");
        return Ok(());
    }
    
    // Show current environment
    for var in &token_vars {
        if let Ok(value) = env::var(var) {
            println!("✅ {}: {}...", var, &value[..std::cmp::min(10, value.len())]);
            break;
        }
    }
    
    if let Ok(project_id) = env::var("CI_PROJECT_ID") {
        println!("✅ CI_PROJECT_ID: {}", project_id);
    }
    
    if let Ok(gitlab_url) = env::var("GITLAB_URL") {
        println!("✅ GITLAB_URL: {}", gitlab_url);
    } else {
        println!("ℹ️  GITLAB_URL: Using default (https://gitlab.com/api/v4/projects/)");
    }
    
    // Optional variables
    if let Ok(pipeline_id) = env::var("CI_PIPELINE_ID") {
        println!("✅ CI_PIPELINE_ID: {}", pipeline_id);
    }
    
    if let Ok(project_url) = env::var("CI_PROJECT_URL") {
        println!("✅ CI_PROJECT_URL: {}", project_url);
    }
    
    if let Ok(commit_sha) = env::var("CI_COMMIT_SHA") {
        println!("✅ CI_COMMIT_SHA: {}", commit_sha);
    }
    
    println!();
    
    // Validate GitLab connectivity
    match GitLabIssuesClient::validate_gitlab_connection(true).await {
        Ok(()) => {
            println!("🎉 GitLab integration is ready!");
            println!("   You can now use --create-gitlab-issues with your scans");
            println!();
            println!("Example command:");
            println!("  ./verascan \\");
            println!("    --filepath /path/to/your/project \\");
            println!("    --filefilter '*.jar,*.war,*.zip' \\");
            println!("    --pipeline-scan \\");
            println!("    --project-name 'Your Project' \\");
            println!("    --create-gitlab-issues \\");
            println!("    --debug");
        }
        Err(e) => {
            println!("❌ GitLab validation failed: {}", e);
            println!();
            println!("🔧 Troubleshooting steps:");
            println!("1. Verify your GitLab token has 'api' scope");
            println!("2. Check that the project ID is correct");
            println!("3. Ensure the token has access to the project");
            println!("4. Verify GitLab URL is accessible");
            println!("5. Check network connectivity to GitLab instance");
            
            return Err(e.into());
        }
    }
    
    Ok(())
}