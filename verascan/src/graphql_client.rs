//! GraphQL client using centralized HTTP client
//!
//! This module demonstrates how to use the centralized RobustHttpClient
//! for GraphQL API integrations, maintaining all robust networking features.

use crate::http_client::{
    AuthStrategy, HttpClientConfigBuilder, HttpClientError, RobustHttpClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// GraphQL request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "operationName")]
    pub operation_name: Option<String>,
}

/// GraphQL response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<GraphQLError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// GraphQL error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<GraphQLLocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// GraphQL error location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLLocation {
    pub line: u32,
    pub column: u32,
}

/// Type alias for GraphQL client errors (using consolidated HTTP client error)
pub type GraphQLClientError = HttpClientError;

/// GraphQL client configuration
#[derive(Clone, Debug)]
pub struct GraphQLClientConfig {
    pub endpoint: String,
    pub auth_token: Option<String>,
    pub custom_headers: HashMap<String, String>,
    pub env_prefix: String,
}

impl GraphQLClientConfig {
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            auth_token: None,
            custom_headers: HashMap::new(),
            env_prefix: "VERASCAN".to_string(),
        }
    }

    #[must_use]
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    #[must_use]
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.custom_headers.insert(key, value);
        self
    }

    #[must_use]
    pub fn with_env_prefix(mut self, prefix: String) -> Self {
        self.env_prefix = prefix;
        self
    }
}

/// GraphQL client with robust networking capabilities
pub struct GraphQLClient {
    http_client: RobustHttpClient,
    config: GraphQLClientConfig,
}

impl GraphQLClient {
    /// Create a new GraphQL client
    pub fn new(config: GraphQLClientConfig) -> Result<Self, GraphQLClientError> {
        let mut builder =
            HttpClientConfigBuilder::for_api_client(config.endpoint.clone(), &config.env_prefix)
                .with_api("GraphQL");

        // Apply authentication if provided
        if let Some(ref token) = config.auth_token {
            builder = builder.with_auth_strategy(AuthStrategy::Bearer(token.clone()))?;
        }

        // Apply custom headers if any
        if !config.custom_headers.is_empty() {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );

            for (key, value) in &config.custom_headers {
                let header_name: reqwest::header::HeaderName = key.parse().map_err(|e| {
                    HttpClientError::ConfigurationError(format!("Invalid header name '{key}': {e}"))
                })?;
                let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|e| {
                    HttpClientError::ConfigurationError(format!(
                        "Invalid header value for '{key}': {e}"
                    ))
                })?;
                headers.insert(header_name, header_value);
            }
            builder = builder.with_headers(headers);
        }

        let http_config = builder.build();
        let http_client = RobustHttpClient::new(http_config)?;

        Ok(Self {
            http_client,
            config,
        })
    }

    /// Execute a GraphQL query
    pub async fn query<T>(
        &self,
        query: &str,
        variables: Option<Value>,
    ) -> Result<T, GraphQLClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
            operation_name: None,
        };

        let response: GraphQLResponse = self.http_client.post("", &request).await?;

        // Check for GraphQL errors
        if let Some(errors) = response.errors {
            let error_messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
            return Err(HttpClientError::GraphQLError(error_messages.join("; ")));
        }

        // Extract and deserialize data
        match response.data {
            Some(data) => {
                let result: T = serde_json::from_value(data)?;
                Ok(result)
            }
            None => Err(HttpClientError::GraphQLError(
                "No data returned".to_string(),
            )),
        }
    }

    /// Execute a GraphQL mutation
    pub async fn mutate<T>(
        &self,
        mutation: &str,
        variables: Option<Value>,
    ) -> Result<T, GraphQLClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        // Mutations are executed the same way as queries in GraphQL
        self.query(mutation, variables).await
    }

    /// Execute a raw GraphQL request and return the full response
    pub async fn execute_raw(
        &self,
        request: &GraphQLRequest,
    ) -> Result<GraphQLResponse, GraphQLClientError> {
        let response: GraphQLResponse = self.http_client.post("", request).await?;
        Ok(response)
    }

    /// Test connectivity to the GraphQL endpoint
    pub async fn test_connectivity(&self) -> Result<(), GraphQLClientError> {
        // Use a simple introspection query to test connectivity
        let introspection_query = r"
            query IntrospectionQuery {
                __schema {
                    queryType {
                        name
                    }
                }
            }
        ";

        let request = GraphQLRequest {
            query: introspection_query.to_string(),
            variables: None,
            operation_name: Some("IntrospectionQuery".to_string()),
        };

        HttpClientError::print_connectivity_test("GraphQL");

        let response: GraphQLResponse = self.http_client.post("", &request).await?;

        if response.errors.is_some() {
            let errors = response.errors.unwrap();
            let error_messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
            return Err(HttpClientError::GraphQLError(format!(
                "Connectivity test failed: {}",
                error_messages.join("; ")
            )));
        }

        HttpClientError::print_connectivity_success("GraphQL");

        Ok(())
    }

    /// Get the endpoint URL
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }
}

/// Example GitHub GraphQL client implementation
pub struct GitHubGraphQLClient {
    client: GraphQLClient,
}

impl GitHubGraphQLClient {
    /// Create a new GitHub GraphQL client
    pub fn new(token: String) -> Result<Self, GraphQLClientError> {
        let config = GraphQLClientConfig::new("https://api.github.com/graphql".to_string())
            .with_auth_token(token);

        let client = GraphQLClient::new(config)?;

        Ok(Self { client })
    }

    /// Get repository information
    pub async fn get_repository(
        &self,
        owner: &str,
        name: &str,
    ) -> Result<Value, GraphQLClientError> {
        let query = r"
            query GetRepository($owner: String!, $name: String!) {
                repository(owner: $owner, name: $name) {
                    id
                    name
                    description
                    url
                    defaultBranchRef {
                        name
                    }
                    languages(first: 10) {
                        nodes {
                            name
                            color
                        }
                    }
                    vulnerabilityAlerts(first: 10) {
                        nodes {
                            id
                            createdAt
                            state
                            securityVulnerability {
                                package {
                                    name
                                }
                                advisory {
                                    summary
                                    severity
                                }
                            }
                        }
                    }
                }
            }
        ";

        let variables = json!({
            "owner": owner,
            "name": name
        });

        self.client.query(query, Some(variables)).await
    }

    /// Create an issue
    pub async fn create_issue(
        &self,
        repository_id: &str,
        title: &str,
        body: &str,
        labels: Vec<String>,
    ) -> Result<Value, GraphQLClientError> {
        let mutation = r"
            mutation CreateIssue($repositoryId: ID!, $title: String!, $body: String!, $labelIds: [ID!]) {
                createIssue(input: {
                    repositoryId: $repositoryId,
                    title: $title,
                    body: $body,
                    labelIds: $labelIds
                }) {
                    issue {
                        id
                        number
                        title
                        url
                        state
                    }
                }
            }
        ";

        let variables = json!({
            "repositoryId": repository_id,
            "title": title,
            "body": body,
            "labelIds": labels
        });

        self.client.mutate(mutation, Some(variables)).await
    }

    /// Test connectivity to GitHub GraphQL API
    pub async fn test_connectivity(&self) -> Result<(), GraphQLClientError> {
        self.client.test_connectivity().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_request_serialization() {
        let request = GraphQLRequest {
            query: "query { user { name } }".to_string(),
            variables: Some(json!({"id": "123"})),
            operation_name: Some("GetUser".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("query"));
        assert!(json.contains("variables"));
        assert!(json.contains("operationName"));
    }

    #[test]
    fn test_graphql_response_deserialization() {
        let response_json = r#"{
            "data": {
                "user": {
                    "name": "John Doe"
                }
            },
            "errors": null
        }"#;

        let response: GraphQLResponse = serde_json::from_str(response_json).unwrap();
        assert!(response.data.is_some());
        assert!(response.errors.is_none());

        if let Some(data) = response.data {
            assert_eq!(data["user"]["name"], "John Doe");
        }
    }

    #[test]
    fn test_graphql_error_response() {
        let response_json = r#"{
            "data": null,
            "errors": [
                {
                    "message": "Field 'invalidField' doesn't exist on type 'User'",
                    "locations": [{"line": 2, "column": 5}],
                    "path": ["user", "invalidField"]
                }
            ]
        }"#;

        let response: GraphQLResponse = serde_json::from_str(response_json).unwrap();
        assert!(response.data.is_none());
        assert!(response.errors.is_some());

        if let Some(errors) = response.errors {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].message.contains("invalidField"));
        }
    }

    #[test]
    fn test_graphql_client_config() {
        let config = GraphQLClientConfig::new("https://api.example.com/graphql".to_string())
            .with_auth_token("test-token".to_string())
            .with_header("X-Custom-Header".to_string(), "custom-value".to_string());

        assert_eq!(config.endpoint, "https://api.example.com/graphql");
        assert_eq!(
            config.custom_headers.get("X-Custom-Header"),
            Some(&"custom-value".to_string())
        );
        // Debug functionality removed from config
        assert_eq!(config.auth_token, Some("test-token".to_string()));
    }

    #[tokio::test]
    async fn test_graphql_client_creation() {
        let config = GraphQLClientConfig::new("https://api.example.com/graphql".to_string());

        let client = GraphQLClient::new(config);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.endpoint(), "https://api.example.com/graphql");
    }
}
