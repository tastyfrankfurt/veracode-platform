# Vault Integration for Verascan

## Overview

Verascan now supports HashiCorp Vault for secure credential management. This integration allows you to store Veracode API credentials in Vault and retrieve them automatically during runtime, providing enhanced security and centralized credential management.

## Features

- **Priority-based credential loading**: Vault credentials are checked first, falling back to environment variables
- **OIDC/JWT authentication**: Secure authentication with Vault using OIDC tokens
- **Retry logic**: Robust error handling with exponential backoff for network issues
- **Input validation**: Comprehensive validation of all Vault configuration parameters
- **Debug logging**: Detailed logging for troubleshooting credential loading issues
- **Secure credential handling**: Debug redaction prevents credential exposure in logs

## Environment Variables

### Vault Configuration (Priority 1)

When these variables are present, Verascan will attempt to load credentials from Vault:

```bash
# Required Vault Configuration
export VAULT_CLI_ADDR="https://vault.example.com"        # Vault server URL (HTTPS only)
export VAULT_CLI_JWT="your-jwt-token"                    # JWT token for OIDC auth
export VAULT_CLI_ROLE="veracode-role"                    # Vault role name
export VAULT_CLI_SECRET_PATH="secret/veracode/api"       # Path to secret containing credentials

# Optional Vault Configuration  
export VAULT_CLI_NAMESPACE="my-namespace"                # Vault namespace (if using Vault Enterprise)
export VAULT_CLI_AUTH_PATH="auth/jwt"                    # Vault auth path (default: auth/jwt)
```

### Fallback Configuration (Priority 2)

If Vault configuration is not available, Verascan falls back to direct environment variables:

```bash
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"
```

### Network Configuration

Existing network configuration options apply to Vault connections:

```bash
export VERASCAN_DISABLE_CERT_VALIDATION=true            # Disable TLS verification (dev only)
```

## Vault Secret Structure

The secret at `VAULT_CLI_SECRET_PATH` must contain the following keys:

```json
{
  "VERACODE_API_ID": "your-veracode-api-id",
  "VERACODE_API_KEY": "your-veracode-api-key"
}
```

## Auth Path Configuration

The `VAULT_CLI_AUTH_PATH` environment variable allows you to specify a custom authentication path for your Vault setup. This is useful when your Vault auth methods are mounted at non-standard paths.

### Default Behavior
If not specified, Verascan uses `auth/jwt` as the default auth path.

### Common Auth Path Examples

| Auth Method | Example Path | Description |
|-------------|--------------|-------------|
| JWT/OIDC | `auth/jwt` | Default JWT authentication (default) |
| OIDC | `auth/oidc` | Custom OIDC authentication |
| Kubernetes | `auth/kubernetes` | Kubernetes service account auth |
| AppRole | `auth/approle` | AppRole authentication |
| AWS | `auth/aws` | AWS IAM authentication |
| Direct Mount | `jwt` | Direct mount point without `auth/` prefix |

### Usage
```bash
# Use default JWT auth (no need to set)
# VAULT_CLI_AUTH_PATH is automatically set to "auth/jwt"

# Use custom OIDC auth path
export VAULT_CLI_AUTH_PATH="auth/oidc"

# Use Kubernetes auth
export VAULT_CLI_AUTH_PATH="auth/kubernetes"

# Use direct mount point
export VAULT_CLI_AUTH_PATH="jwt"
```

## Usage Examples

### Basic Vault Setup

```bash
# Set Vault configuration
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="eyJhbGciOiJSUzI1NiIs..."
export VAULT_CLI_ROLE="veracode-scanner"  
export VAULT_CLI_SECRET_PATH="secret/security/veracode"
export VAULT_CLI_AUTH_PATH="auth/jwt"  # Optional: Use default JWT auth

# Run verascan - credentials will be loaded from Vault
verascan pipeline --app-name MyApp --scan-name test-scan
```

### With Namespace (Vault Enterprise)

```bash
export VAULT_CLI_ADDR="https://vault.enterprise.com"
export VAULT_CLI_JWT="eyJhbGciOiJSUzI1NiIs..."
export VAULT_CLI_ROLE="veracode-role"
export VAULT_CLI_SECRET_PATH="secret/data/veracode/api"
export VAULT_CLI_NAMESPACE="security-team"
export VAULT_CLI_AUTH_PATH="auth/oidc"  # Custom OIDC auth path

verascan pipeline --app-name MyApp --scan-name test-scan
```

### With Custom Secret Engine

```bash
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="eyJhbGciOiJSUzI1NiIs..."
export VAULT_CLI_ROLE="veracode-scanner"
# Use custom secret engine named 'secrets'
export VAULT_CLI_SECRET_PATH="veracode/api/credentials@secrets"
export VAULT_CLI_AUTH_PATH="auth/kubernetes"  # Kubernetes auth

verascan pipeline --app-name MyApp --scan-name test-scan
```

### Fallback to Environment Variables

```bash
# If Vault is unavailable, set traditional environment variables
export VERACODE_API_ID="your-api-id"
export VERACODE_API_KEY="your-api-key"

verascan pipeline --app-name MyApp --scan-name test-scan
```

## Validation Rules

### Vault Address
- Must use HTTPS protocol
- Maximum length: 150 characters

### JWT Token  
- Maximum length: 20,000 characters
- Allowed characters: alphanumeric, hyphens, underscores, periods

### Role Name
- Length: 1-100 characters
- Cannot be empty

### Secret Path
- Length: 1-200 characters  
- Cannot be empty
- Supports custom secret engines using format: `path@engine` (e.g., `secret/data/app@kvv2`)
- Defaults to `kvv2` engine if no engine specified

### Auth Path
- Maximum length: 100 characters
- Allowed characters: alphanumeric, forward slashes, hyphens, underscores
- Default value: `auth/jwt` (if not specified)
- Examples: `auth/jwt`, `auth/oidc`, `auth/kubernetes`, `jwt`

## Error Handling

### Retry Logic
- **Authentication**: Up to 60 seconds with exponential backoff
- **Secret Retrieval**: Up to 45 seconds with exponential backoff
- **Token Revocation**: Up to 30 seconds with exponential backoff
- **Initial Delay**: 250-500ms depending on operation
- **Max Delay**: 5-10 seconds depending on operation
- **Multiplier**: 2.0

### Enhanced Error Detection
- **TLS/Certificate Errors**: Automatically detected and not retried
- **Authentication Errors**: HTTP 401/403 errors are not retried
- **Network Errors**: Connection, timeout, and rate limit errors are retried
- **Client Errors**: HTTP 4xx errors (except auth) are not retried
- **Server Errors**: HTTP 5xx errors are retried with backoff

### Error Types
- `VaultConfigError`: Missing or invalid configuration
- `VaultAuthError`: Authentication failures
- `VaultSecretError`: Secret retrieval failures
- `ValidationError`: Input validation failures

## Logging

Enable debug logging to troubleshoot Vault integration:

```bash
export RUST_LOG=debug
verascan pipeline --app-name MyApp --scan-name test-scan
```

Log levels:
- `INFO`: Successful operations and credential source
- `WARN`: Retry attempts and fallback notifications  
- `DEBUG`: Detailed operation flow
- `ERROR`: Critical failures

## Security Considerations

- **Automatic Token Revocation**: Vault tokens are automatically revoked after successful credential retrieval
- **Memory-only Credentials**: Credentials remain in memory only, never written to disk
- **Secure Logging**: Vault credentials are never logged or printed
- **JWT Token Validation**: JWT tokens are validated for format and length
- **Debug Redaction**: All secrets use secure debug redaction
- **TLS Enforcement**: TLS verification is enforced by default
- **Input Validation**: Comprehensive input validation prevents injection attacks
- **Certificate Error Detection**: Enhanced TLS/certificate error detection and handling

## Migration Guide

### From Environment Variables

1. Store existing credentials in Vault:
   ```bash
   vault kv put secret/veracode/api VERACODE_API_ID="your-id" VERACODE_API_KEY="your-key"
   ```

2. Set Vault configuration:
   ```bash
   export VAULT_CLI_ADDR="https://your-vault.com"
   export VAULT_CLI_JWT="your-jwt-token"
   export VAULT_CLI_ROLE="your-role"
   export VAULT_CLI_SECRET_PATH="secret/veracode/api"
   ```

3. Remove old environment variables:
   ```bash
   unset VERACODE_API_ID
   unset VERACODE_API_KEY
   ```

4. Test the integration:
   ```bash
   RUST_LOG=info verascan pipeline --app-name test --scan-name vault-test
   ```

### Gradual Rollout

For gradual deployment, keep both Vault and environment variables configured. Verascan will prefer Vault but fall back to environment variables if Vault is unavailable.

## Troubleshooting

### Common Issues

1. **"VAULT_CLI_ADDR not found"**
   - Ensure all required Vault environment variables are set

2. **"Vault address must use HTTPS"**
   - Update VAULT_CLI_ADDR to use https:// protocol

3. **"Vault authentication failed"**
   - Verify JWT token is valid and not expired
   - Check Vault role permissions
   - Ensure namespace is correct (if using Vault Enterprise)

4. **"Failed to retrieve secret"**
   - Verify secret path exists in Vault
   - Check role has read permissions for the secret path
   - Ensure secret contains VERACODE_API_ID and VERACODE_API_KEY keys

### Debug Commands

```bash
# Test Vault connectivity
vault auth -method=oidc role=your-role jwt=your-jwt

# Verify secret exists
vault kv get secret/veracode/api

# Check Vault policies
vault policy read your-policy
```