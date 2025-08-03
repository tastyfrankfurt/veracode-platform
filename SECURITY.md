# Security Policy

## Security Improvements

This project has implemented comprehensive security measures to protect all sensitive information including Veracode API credentials and GitLab tokens:

### Secure Token Handling

#### GitLab Token Security
**Location**: `verascan/src/gitlab_issues.rs:14-36`

- **SecureToken Wrapper**: Implemented a secure wrapper for GitLab private tokens that automatically redacts values in debug output
- **Custom Debug Trait**: GitLabConfig now has a custom Debug implementation that shows `api_token: [REDACTED]` instead of exposing the actual token
- **Comprehensive Testing**: Added tests to verify token redaction works correctly in all scenarios

#### Veracode API Credentials Security
**Location**: `verascan/src/credentials.rs` and `veracode-api/src/lib.rs`

- **SecureApiCredentials Wrapper**: Comprehensive wrapper for Veracode API credentials in verascan package
  - `SecureApiId` and `SecureApiKey` wrappers prevent credential exposure
  - `SecureApiCredentials` struct manages both credentials securely
- **Veracode-API Package Security**: Secure wrappers in the core API library
  - `SecureVeracodeApiId` and `SecureVeracodeApiKey` wrappers in `VeracodeConfig`
  - Custom Debug implementation for `ApiCredential` struct in identity module
- **Automatic Redaction**: All sensitive credentials show `[REDACTED]` in debug output
- **Backward Compatibility**: All existing code continues to work unchanged

### Password Redaction in URLs

**Location**: `verascan/src/scan.rs:324-347`

- **Git URL Protection**: Implemented `redact_url_password` function that safely logs Git URLs
- **Format**: URLs with passwords are logged as `username:[REDACTED]@host` to preserve useful information while protecting credentials
- **Comprehensive Coverage**: Handles various URL formats including HTTP, HTTPS, and SSH

### Security Features

1. **Comprehensive Token Protection**: All sensitive credentials are secured across the entire codebase
   - GitLab private tokens (`PRIVATE_TOKEN`, `CI_TOKEN`, `GITLAB_TOKEN`)
   - Veracode API credentials (`VERACODE_API_ID`, `VERACODE_API_KEY`)
   - API credentials in both verascan and veracode-api packages

2. **Automatic Debug Redaction**: All sensitive tokens show `[REDACTED]` in debug output
   - Custom Debug implementations prevent accidental credential exposure
   - Secure wrappers ensure credentials are never leaked in logs

3. **Safe Debug Output**: Debug traits have been carefully implemented to prevent credential exposure
   - `VeracodeConfig` shows structure but redacts credentials
   - `GitLabConfig` shows configuration but redacts tokens
   - `ApiCredential` struct redacts API keys while showing metadata

4. **URL Sanitization**: Git remote URLs are sanitized to remove password information before logging

5. **Comprehensive Test Coverage**: 18+ tests ensure security measures work correctly
   - Debug redaction tests for all credential types
   - Access method tests to ensure functionality
   - Integration tests for secure credential handling

6. **Backward Compatibility**: All existing code continues to work unchanged
   - No breaking changes to existing APIs
   - Examples continue to work without modification
   - Secure wrappers are transparent to existing code

### Implementation Details

#### SecureToken Wrapper (GitLab)
```rust
pub struct SecureToken(String);

impl SecureToken {
    pub fn new(token: String) -> Self {
        SecureToken(token)
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecureToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
```

#### SecureApiCredentials Wrapper (Veracode)
```rust
#[derive(Clone)]
pub struct SecureApiCredentials {
    pub api_id: Option<SecureApiId>,
    pub api_key: Option<SecureApiKey>,
}

#[derive(Clone)]
pub struct SecureApiId(String);

#[derive(Clone)]
pub struct SecureApiKey(String);

impl std::fmt::Debug for SecureApiId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Debug for SecureApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
```

#### VeracodeConfig Security (veracode-api)
```rust
#[derive(Clone)]
pub struct VeracodeConfig {
    pub api_id: SecureVeracodeApiId,
    pub api_key: SecureVeracodeApiKey,
    // ... other fields
}

impl std::fmt::Debug for VeracodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VeracodeConfig")
            .field("api_id", &self.api_id)      // Shows [REDACTED]
            .field("api_key", &self.api_key)    // Shows [REDACTED]
            .field("base_url", &self.base_url)
            // ... other fields
            .finish()
    }
}
```

#### URL Redaction
```rust
pub fn redact_url_password(url: &str) -> String {
    // Implementation redacts passwords while preserving useful information
    // Example: https://user:pass@github.com/repo.git -> https://user:[REDACTED]@github.com/repo.git
}
```

## Reporting Security Issues

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the project maintainers
3. Include detailed information about the vulnerability
4. Allow reasonable time for the issue to be addressed

## Security Best Practices

When using this project:

1. **Environment Variables**: Store sensitive credentials in environment variables, not in code
2. **Debug Logs**: Be cautious with debug output in production environments
3. **Token Scopes**: Use minimum required scopes for GitLab and Veracode tokens
4. **Regular Updates**: Keep dependencies and the project updated
5. **Access Control**: Limit access to systems that have these credentials

## Dependencies

This project regularly updates dependencies to address security vulnerabilities. Run `cargo audit` to check for known security issues in dependencies.