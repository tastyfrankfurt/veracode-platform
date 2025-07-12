# Veracode Platform Client Library

[![Rust](https://img.shields.io/badge/rust-1.70%2B-brightgreen.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/veracode-platform.svg)](https://crates.io/crates/veracode-platform)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Documentation](https://docs.rs/veracode-platform/badge.svg)](https://docs.rs/veracode-platform)

A comprehensive Rust client library for the Veracode security platform, providing type-safe and ergonomic access to Applications, Identity, Pipeline Scan, Sandbox, Policy, and Build APIs.

## ✨ Features

- 🔐 **HMAC Authentication** - Built-in Veracode API credential support with automatic signature generation
- 🌍 **Multi-Regional Support** - Automatic endpoint routing for Commercial, European, and Federal regions
- 🔄 **Smart API Routing** - Automatically uses REST or XML APIs based on operation requirements
- 📱 **Applications API** - Complete application lifecycle management via REST API
- 👥 **Identity API** - User and team management via REST API
- 🔍 **Pipeline Scan API** - CI/CD security scanning via REST API
- 🧪 **Sandbox API** - Development sandbox management via REST API
- 🔨 **Build API** - Build management and SAST operations via XML API
- 📊 **Scan API** - File upload and scan operations via XML API
- 📋 **Policy API** - Security policy management and compliance evaluation via REST API
- 🚀 **Async/Await** - Built on tokio for high-performance concurrent operations
- ⚡ **Type-Safe** - Full Rust type safety with comprehensive serde serialization
- 📊 **Rich Data Types** - Comprehensive data structures for all API responses
- 🔧 **Workflow Helpers** - High-level operations combining multiple API calls

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
veracode-platform = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use veracode_platform::{VeracodeConfig, VeracodeClient, VeracodeRegion};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client for your region
    let config = VeracodeConfig::new(
        std::env::var("VERACODE_API_ID")?,
        std::env::var("VERACODE_API_KEY")?,
    ).with_region(VeracodeRegion::Commercial); // Commercial (default), European, or Federal
    
    // Create client
    let client = VeracodeClient::new(config)?;
    
    // Use Applications API (REST)
    let apps = client.get_all_applications().await?;
    println!("Found {} applications", apps.len());
    
    // Use Pipeline Scan API (REST)
    let pipeline = client.pipeline_api();
    // ... pipeline operations
    
    // Use Scan API for file uploads (XML)
    let scan_api = client.scan_api();
    // ... scan operations
    
    Ok(())
}
```

## 🌍 Regional Support

The library automatically handles regional endpoints for both REST and XML APIs:

```rust
use veracode_platform::{VeracodeConfig, VeracodeRegion};

// Commercial region (default)
let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
    .with_region(VeracodeRegion::Commercial);
// REST: api.veracode.com | XML: analysiscenter.veracode.com

// European region
let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
    .with_region(VeracodeRegion::European);
// REST: api.veracode.eu | XML: analysiscenter.veracode.eu

// US Federal region
let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
    .with_region(VeracodeRegion::Federal);
// REST: api.veracode.us | XML: analysiscenter.veracode.us
```

## 📚 API Modules

### Applications API (REST)
Complete application lifecycle management:

```rust
// List all applications
let apps = client.get_all_applications().await?;

// Get specific application
let app_query = ApplicationQuery {
    name: Some("MyApp".to_string()),
    ..Default::default()
};
let app = client.get_application(app_query).await?;

// Create new application
let create_request = CreateApplicationRequest {
    name: "New App".to_string(),
    description: Some("My new application".to_string()),
    business_unit_id: Some(12345),
    teams: vec![],
    tags: vec![],
};
let new_app = client.create_application(create_request).await?;
```

### Pipeline Scan API (REST)
CI/CD security scanning:

```rust
use veracode_platform::pipeline::{CreateScanRequest, DevStage};

let pipeline = client.pipeline_api();

// Create a pipeline scan
let scan_request = CreateScanRequest {
    binary_name: "my-app.jar".to_string(),
    binary_size: file_data.len() as u64,
    binary_hash: calculate_sha256(&file_data),
    project_name: "My Project".to_string(),
    project_uri: Some("https://github.com/user/repo".to_string()),
    dev_stage: DevStage::Development,
    app_id: None,
    project_ref: Some("main".to_string()),
    scan_timeout: Some(30),
    plugin_version: None,
    emit_stack_dump: None,
    include_modules: None,
};

let scan_result = pipeline.create_scan(scan_request).await?;
println!("Created scan: {}", scan_result.scan_id);

// Monitor scan status
let scan_info = pipeline.get_scan(&scan_result.scan_id).await?;
println!("Scan status: {:?}", scan_info.status);

// Get findings when complete
if scan_info.status == ScanStatus::Complete {
    let findings = pipeline.get_findings(&scan_result.scan_id).await?;
    println!("Found {} security issues", findings.len());
}
```

### Identity API (REST)
User and team management:

```rust
let identity = client.identity_api();

// List users
let users = identity.get_users(None).await?;

// Create new user
let create_user = CreateUserRequest {
    email: "user@example.com".to_string(),
    first_name: "John".to_string(),
    last_name: "Doe".to_string(),
    user_type: UserType::User,
    roles: vec![],
    teams: vec![],
};
let new_user = identity.create_user(create_user).await?;

// Manage teams
let teams = identity.get_teams().await?;
```

### Sandbox API (REST)
Development sandbox management:

```rust
let sandbox_api = client.sandbox_api();

// List sandboxes for an application
let sandboxes = sandbox_api.get_sandboxes("app-guid").await?;

// Create new sandbox
let create_request = CreateSandboxRequest {
    name: "Development Sandbox".to_string(),
    auto_recreate: Some(false),
    custom_fields: vec![],
};
let sandbox = sandbox_api.create_sandbox("app-guid", create_request).await?;
```

### Scan API (XML)
File upload and scan operations:

```rust
let scan_api = client.scan_api();

// Upload file for scanning
let upload_request = UploadFileRequest {
    app_id: "12345".to_string(),
    file_path: "/path/to/file.jar".to_string(),
    sandbox_id: Some("sandbox-guid".to_string()),
};

let uploaded_file = scan_api.upload_file(upload_request).await?;
println!("Uploaded: {}", uploaded_file.file_name);

// Start pre-scan
let pre_scan = scan_api.begin_pre_scan(BeginPreScanRequest {
    app_id: "12345".to_string(),
    sandbox_id: Some("sandbox-guid".to_string()),
    scan_all_nonfatal_top_level_modules: Some(true),
    auto_scan: Some(true),
});
```

### Policy API (REST)
Security policy and compliance management:

```rust
let policy_api = client.policy_api();

// Get organizational policies
let policies = policy_api.get_policies().await?;

// Evaluate policy compliance
let compliance = policy_api.evaluate_policy_compliance(
    &app_guid, 
    &policy_guid, 
    None
).await?;
println!("Compliance status: {:?}", compliance.status);
println!("Score: {}/100", compliance.score.unwrap_or(0));

// Initiate policy-based scan
let scan_request = PolicyScanRequest {
    application_guid: app_guid.to_string(),
    policy_guid: policy_guid.to_string(),
    scan_type: ScanType::Static,
    sandbox_guid: None,
    config: None,
};
let scan_result = policy_api.initiate_policy_scan(scan_request).await?;
```

### Build API (XML)
Build management and SAST operations:

```rust
let build_api = client.build_api();

// Get build list for application
let builds = build_api.get_build_list(GetBuildListRequest {
    app_id: "12345".to_string(),
    sandbox_id: None,
}).await?;

// Create new build
let create_build = CreateBuildRequest {
    app_id: "12345".to_string(),
    version: "1.0.0".to_string(),
    sandbox_id: None,
    lifecycle_stage: None,
    launch_date: None,
};
let build = build_api.create_build(create_build).await?;
```

### Workflow Helpers
High-level operations combining multiple API calls:

```rust
let workflow = client.workflow();

// Complete application workflow
let workflow_config = WorkflowConfig {
    app_name: "My Application".to_string(),
    build_version: "1.0.0".to_string(),
    file_paths: vec!["/path/to/app.jar".to_string()],
    scan_timeout: Some(45),
    delete_incomplete_scans: true,
};

let result = workflow.run_complete_workflow(workflow_config).await?;
println!("Workflow completed: {:?}", result);
```

## 🔐 Authentication

### Environment Variables
Set your Veracode API credentials:

```bash
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"
```

### Direct Configuration
Or pass credentials directly:

```rust
let config = VeracodeConfig::new(
    "your-api-id".to_string(),
    "your-api-key".to_string()
);
```

### Development Mode
Disable certificate validation for development environments:

```bash
export VERASCAN_DISABLE_CERT_VALIDATION="true"
```

Or in code:
```rust
let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
    .with_certificate_validation_disabled(); // Only for development!
```

## 🎛️ Feature Flags

Enable only the APIs you need to reduce compile time and binary size:

```toml
[dependencies]
veracode-platform = { version = "0.1.0", features = ["pipeline", "applications"] }
```

Available features:
- `applications` - Applications API support
- `identity` - Identity API support
- `pipeline` - Pipeline Scan API support
- `sandbox` - Sandbox API support
- `policy` - Policy API support
- `default` - All APIs enabled

## 🧪 Examples

The library includes comprehensive examples for each API:

```bash
# Set up credentials first
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

# Applications API example
cargo run --example application_lifecycle

# Identity API example
cargo run --example identity_lifecycle

# Pipeline Scan API example
cargo run --example pipeline_scan_lifecycle

# Sandbox API example
cargo run --example sandbox_lifecycle

# Policy API example
cargo run --example policy_lifecycle

# Basic usage example
cargo run --example basic_usage

# Build lifecycle example
cargo run --example build_lifecycle_example

# Large file upload example
cargo run --example large_file_upload_example

# XML API workflow validation
cargo run --example xml_api_workflow_validation
```

## 🏗️ Architecture

### API Type Routing
The library automatically routes operations to the correct API type:

- **REST API (`api.veracode.*`)**: Applications, Identity, Pipeline, Policy, Sandbox management
- **XML API (`analysiscenter.veracode.*`)**: Build management, Scan operations, Legacy workflows

### Smart Client Management
The client automatically creates specialized instances for different API types:

```rust
let client = VeracodeClient::new(config)?;

// REST API modules use the main client
let apps = client.get_all_applications().await?;  // Uses REST
let pipeline = client.pipeline_api();             // Uses REST
let identity = client.identity_api();             // Uses REST

// XML API modules use a specialized XML client internally
let scan_api = client.scan_api();                 // Uses XML
let build_api = client.build_api();               // Uses XML
```

### Regional Endpoint Management
All regional variants are supported with automatic endpoint resolution:

| Region | REST Endpoint | XML Endpoint |
|--------|---------------|--------------|
| Commercial | `api.veracode.com` | `analysiscenter.veracode.com` |
| European | `api.veracode.eu` | `analysiscenter.veracode.eu` |
| Federal | `api.veracode.us` | `analysiscenter.veracode.us` |

## 🔧 Error Handling

The library provides comprehensive error types for robust error handling:

```rust
use veracode_platform::{VeracodeError, pipeline::PipelineError, sandbox::SandboxError};

// Pipeline API error handling
match pipeline.get_findings(&scan_id).await {
    Ok(findings) => println!("Found {} issues", findings.len()),
    Err(PipelineError::FindingsNotReady) => {
        println!("Scan still processing, try again later");
    },
    Err(PipelineError::ApiError(VeracodeError::Unauthorized)) => {
        println!("Check your API credentials");
    },
    Err(PipelineError::ApiError(VeracodeError::NotFound(msg))) => {
        println!("Scan not found: {}", msg);
    },
    Err(e) => println!("Error: {}", e),
}

// Sandbox API error handling
match sandbox_api.get_sandboxes("app-guid").await {
    Ok(sandboxes) => println!("Found {} sandboxes", sandboxes.len()),
    Err(SandboxError::InvalidApplicationGuid(guid)) => {
        println!("Invalid application GUID: {}", guid);
    },
    Err(SandboxError::ApiError(VeracodeError::Authentication(msg))) => {
        println!("Authentication failed: {}", msg);
    },
    Err(e) => println!("Error: {}", e),
}
```

### Common Error Types

| Error Type | Description |
|------------|-------------|
| `VeracodeError::Authentication` | Invalid API credentials or signature issues |
| `VeracodeError::NotFound` | Requested resource doesn't exist |
| `VeracodeError::InvalidResponse` | API returned unexpected response format |
| `VeracodeError::Http` | Network or HTTP-level errors |
| `VeracodeError::Serialization` | JSON parsing or serialization errors |

## 📊 Data Types

### Core Types
```rust
// Application management
pub struct Application {
    pub guid: String,
    pub name: String,
    pub description: Option<String>,
    // ... more fields
}

// Pipeline scanning
pub struct Finding {
    pub issue_id: u32,
    pub issue_type: String,
    pub issue_type_id: String,
    pub cwe_id: String,
    pub severity: Severity,
    // ... more fields
}

// Identity management
pub struct User {
    pub user_id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub user_type: UserType,
    // ... more fields
}
```

### Enums and Status Types
```rust
// Scan status tracking
#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Complete,
    Failed,
    Cancelled,
}

// Security severity levels
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
    Informational,
}

// Development stages
#[derive(Debug, Clone, PartialEq)]
pub enum DevStage {
    Development,
    Testing,
    Release,
}
```

## 🔬 Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test --test applications_api
```

Note: Integration tests require valid Veracode API credentials and may create/modify resources in your Veracode account.

## 📖 Documentation

Generate and view the documentation:

```bash
# Build and open documentation
cargo doc --open

# Build documentation for all features
cargo doc --all-features --open
```

## 🏷️ Versioning

This library follows [Semantic Versioning](https://semver.org/):

- **Major version** changes indicate breaking API changes
- **Minor version** changes add functionality in a backward-compatible manner
- **Patch version** changes include backward-compatible bug fixes

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd veracode-workspace/veracode-api

# Run tests
cargo test

# Check formatting
cargo fmt -- --check

# Run lints
cargo clippy -- -D warnings

# Build documentation
cargo doc --all-features
```

## 📜 License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## 🆘 Support

- 📚 **Documentation**: [docs.rs/veracode-platform](https://docs.rs/veracode-platform)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/veracode-platform/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/veracode-platform/discussions)
- 📝 **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

*Built with ❤️ in Rust for the security community*