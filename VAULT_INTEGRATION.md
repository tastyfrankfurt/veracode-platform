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

## Usage Examples

### Basic Vault Setup

```bash
# Set Vault configuration
export VAULT_CLI_ADDR="https://vault.company.com"
export VAULT_CLI_JWT="eyJhbGciOiJSUzI1NiIs..."
export VAULT_CLI_ROLE="veracode-scanner"  
export VAULT_CLI_SECRET_PATH="secret/security/veracode"

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
- Maximum length: 50 characters
- Allowed characters: alphanumeric, hyphens, underscores, periods

### Role Name
- Length: 1-50 characters
- Cannot be empty

### Secret Path
- Length: 1-200 characters  
- Cannot be empty

## Error Handling

### Retry Logic
- **Authentication**: Up to 60 seconds with exponential backoff
- **Secret Retrieval**: Up to 45 seconds with exponential backoff
- **Initial Delay**: 500ms
- **Max Delay**: 8-10 seconds
- **Multiplier**: 2.0

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

- Vault credentials are never logged or printed
- JWT tokens are validated for format and length
- All secrets use secure debug redaction
- TLS verification is enforced by default
- Input validation prevents injection attacks

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