# Authentication Server

A sophisticated, enterprise-grade authentication service built with .NET, providing comprehensive identity management, multi-factor authentication, OAuth integration, and payment processing capabilities. This system is designed with security, scalability, and flexibility in mind, supporting both traditional and modern authentication workflows.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Core Features](#core-features)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Configuration](#configuration-guide)
6. [Getting Started](#getting-started)
7. [API Documentation](#api-documentation)
8. [Security Features](#security-features-and-implementation)

## Project Overview

This Authentication Server is designed as a complete identity management solution that combines modern authentication practices with cloud services integration. It serves as a centralized authentication and authorization system that can be easily integrated with other applications while maintaining high security standards and providing a seamless user experience.

## Core Features

### Authentication Capabilities
- Email and password authentication
- Multi-factor authentication (2FA) with multiple provider options:
  - Email-based verification codes
  - Authenticator apps (TOTP)
  - SMS verification
- OAuth 2.0 and OpenID Connect support
- External identity provider integration (Google, Facebook, etc.)
- JWT-based authentication with refresh token rotation
- Password reset and email verification workflows
- Session management and security

### Authorization Features
- Role-based access control (RBAC)
- Fine-grained permission system
- User role management
- Dynamic security policy enforcement

### Integration Capabilities
- AWS services integration (SES, CloudWatch, Secrets Manager)
- Stripe payment processing
- Event-driven user creation with MassTransit
- Comprehensive logging infrastructure

### Security Features
- CSRF/XSRF protection
- Rate limiting for brute force attack prevention
- Modern password hashing
- SSL/TLS enforcement
- Security headers management
- Request validation
- Secure token handling

## Architecture

The authentication server follows a modular, clean architecture pattern that separates concerns and maintains high cohesion between related functionalities.

### Solution Structure

```
AuthServer/
├── src/
│   ├── AuthServer.Web/              # Main application host
│   ├── AuthServer.Contracts/        # Domain models and interfaces
│   ├── AuthServer.AWS.SDK/          # AWS integration services
│   └── AuthServer.Stripe.SDK/       # Stripe payment integration
```

### Component Overview

#### AuthServer.Web
The main application entry point that handles HTTP requests and orchestrates the authentication workflows. Key components include:

- **Endpoints**: API endpoints organized by functionality (Auth, Roles, Security)
- **Middlewares**: Request processing, exception handling, and logging
- **Extensions**: Service configuration and setup
- **Services**: Core business logic implementation
- **Migrations**: Database schema management

#### AuthServer.Contracts
Contains the core business models, interfaces, and shared contracts:

- **Auth Models**: Request/response models for authentication operations
- **Configuration**: Application configuration models
- **Database**: Entity definitions and database context
- **Exceptions**: Custom exception types for domain-specific errors

#### AuthServer.AWS.SDK
Handles AWS service integrations:

- **CloudWatch**: Application monitoring and logging
- **SES**: Email service for user communications
- **SecretsManager**: Secure configuration management

#### AuthServer.Stripe.SDK
Manages payment processing functionality:

- **Customer Management**: User payment profiles
- **Payment Processing**: Transaction handling
- **Invoice Management**: Billing operations

## Prerequisites

Before setting up the Authentication Server, you'll need to configure several external services and ensure your development environment meets specific requirements:

### Development Environment
- .NET 8.0 SDK or later
- PostgreSQL 13.0 or later
- Redis 6.2 or later for distributed caching (optional, the server uses in-memory caching by default)
- Git for version control
- Visual Studio 2022 or JetBrains Rider

### AWS Services Configuration

The authentication server relies on several AWS services, each requiring specific configuration:

#### AWS Secrets Manager
The application uses a hierarchical structure for managing configuration secrets:
```
authServer/{environment}/shared/{config-type}
```
where:
- `environment` is either "dev" or "prod"
- `config-type` can be "database", "networking", "stripe", "auth", or "cache"

You'll need to create these secrets in AWS Secrets Manager within the eu-central-1 (Frankfurt) region. Each secret should contain JSON-formatted configuration data matching the corresponding configuration model.

#### AWS Simple Email Service (SES)
For handling email communications, you'll need:
- A verified sender domain or email address in SES
- Appropriate sending limits configured
- Production access if you plan to send to non-verified recipients
- SES configured in the same region as your other AWS services

### Stripe Integration
To handle the user creation operations:
- Create a Stripe account
- Obtain API keys (both test and live)
- Configure webhook endpoints

### Required AWS IAM Permissions
Create an IAM user or role with these permissions:

```json
{
    "Version": "2012-10-01",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:ListSecrets"
            ],
            "Resource": "arn:aws:secretsmanager:eu-central-1:*:secret:authServer/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:eu-central-1:*:log-group:/aws/authServer/*"
        }
    ]
}
```

## Configuration Guide

### AWS Secrets Manager Structure

The application uses AWS Secrets Manager to securely store sensitive configuration. Below is the complete configuration structure:

```json
{
  "AuthConfiguration": {
    "CorsAllowOrigin": "https://yourdomain.com",
    "JwtIssuer": "your-issuer",
    "JwtAudience": "your-audience",
    "PrivateKey": "-----BEGIN PRIVATE KEY-----\n...",
    "PublicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "SourceEmail": "noreply@yourdomain.com",
    "SmtpUsername": "AKIAXXXXXXXXXXXXXXXX",
    "SmtpPassword": "your-smtp-password",
    "IdentityProviders": [
      {
        "Name": "Google",
        "ClientId": "your-google-client-id",
        "ClientSecret": "your-google-client-secret",
        "RedirectUri": "https://yourdomain.com/api/auth/external-callback",
        "Scope": "openid email profile",
        "GrantType": "authorization_code",
        "ResponseType": "code",
        "TokenEndpoint": "https://oauth2.googleapis.com/token",
        "UserInfoEndpoint": "https://www.googleapis.com/oauth2/v3/userinfo",
        "FrontEndRedirectUri": "https://yourdomain.com/auth/callback",
        "UserClaims": {
          "sub": "sub",
          "email": "email",
          "name": "name",
          "given_name": "given_name",
          "family_name": "family_name",
          "picture": "picture"
        }
      },
      {
        "Name": "Facebook",
        "ClientId": "your-facebook-client-id",
        "ClientSecret": "your-facebook-client-secret",
        "RedirectUri": "https://yourdomain.com/api/auth/external-callback",
        "Scope": "email public_profile",
        "GrantType": "authorization_code",
        "ResponseType": "code",
        "TokenEndpoint": "https://graph.facebook.com/v12.0/oauth/access_token",
        "UserInfoEndpoint": "https://graph.facebook.com/me",
        "FrontEndRedirectUri": "https://yourdomain.com/auth/callback",
        "UserClaims": {
          "sub": "id",
          "email": "email",
          "name": "name",
          "given_name": "first_name",
          "family_name": "last_name",
          "picture": "picture"
        }
      }
    ]
  },
  "DatabaseConfiguration": {
    "DbConnectionString": "Host=...;Database=...;Username=...;Password=..."
  },
  "StripeConfiguration": {
    "ApiKey": "sk_test_...",
    "PaymentWebhookSecret": "whsec_..."
  }
}
```

## API Documentation

### Authentication Routes (`/api/auth/*`)

The authentication endpoints handle all aspects of user identity and authentication flows.

#### User Registration and Login

```
POST /api/auth/register
```
Creates a new user account. The registration process includes email verification and optional 2FA setup.

Request body:
```json
{
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "profile_picture": "https://example.com/avatar.jpg",
  "password": "securePassword123"
}
```

```
POST /api/auth/login
```
Authenticates a user and returns JWT tokens. Handles 2FA challenges when enabled.

Request body:
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "two_factor_code": "123456"
}
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJ...",
  "refreshToken": "eyJhbGciOiJ...",
  "expiresIn": 3600
}
```

#### Email Verification Flow

```
GET /api/auth/confirm-email/{userId}/{token}
```
Validates email confirmation tokens sent to users upon registration.

```
POST /api/auth/resend-confirmation
```
Resends the confirmation email if the original expires or is lost.

Request body:
```json
{
  "email": "user@example.com"
}
```

#### Password Management

```
POST /api/auth/forgot-password
```
Initiates the password reset flow by sending a reset code via email.

```
POST /api/auth/reset-password
```
Completes the password reset process with a valid reset token.

#### Two-Factor Authentication

```
POST /api/2fa/enable/{type}
```
Enables 2FA for a user account. Supported types include "authenticator", "email", and "sms".

```
POST /api/2fa/verify
```
Verifies 2FA setup or login challenges.

Request body:
```json
{
  "verification_code": "123456"
}
```

```
POST /api/2fa/disable
```
Disables 2FA for a user account (requires authentication).

#### OAuth/External Authentication

```
GET /api/auth/external-login/{provider}
```
Initiates OAuth flow with specified provider (e.g., "google", "facebook").

```
GET /api/auth/external-callback
```
Handles OAuth provider callbacks and user creation/login.

#### Token Management

```
POST /api/auth/refresh
```
Issues new access tokens using a valid refresh token.

Request body:
```json
{
  "refresh_token": "eyJhbGciOiJ..."
}
```

### Role Management Routes (`/api/roles/*`)

These endpoints manage user roles and permissions within the system.

```
GET /api/roles
```
Returns all available roles in the system.

```
POST /api/roles
```
Creates a new role.

```
DELETE /api/roles/{roleName}
```
Removes an existing role.

```
POST /api/users/{userId}/roles
```
Assigns roles to a user.

```
DELETE /api/users/{userId}/roles/{roleName}
```
Removes a role from a user.

```
GET /api/users/{userId}/roles
```
Retrieves all roles assigned to a user.

## Security Features and Implementation

The authentication server implements a comprehensive security architecture built around several core services working together to ensure secure authentication and authorization.

### Token Service Implementation

The token service manages JWT generation and validation using asymmetric RSA encryption:

```csharp
public class TokenService : ITokenService
{
    // Key validation parameters ensure tokens are properly verified
    private readonly TokenValidationParameters _tokenValidationParams;
    
    public async Task<AccessTokenResponse> GetAccessTokenAsync(User user)
    {
        // Generate short-lived 60-minute access token and 24-hour refresh token
        var tokenExpiration = TimeSpan.FromMinutes(60);
        var accessToken = await GenerateToken(user, tokenExpiration);
        var refreshToken = await GenerateToken(user, TimeSpan.FromDays(1));
        
        return new AccessTokenResponse
        { 
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = (int)tokenExpiration.TotalSeconds 
        };
    }
}
```

The tokens contain essential user claims including:
- Subject (user ID)
- Email
- Name (given name and family name)
- Email verification status
- Profile picture
- Stripe customer ID
- User roles

### Security Service Features

The security service handles OAuth state management and token validation:

1. **State Management**: Securely stores authentication parameters in a distributed cache:
```csharp
public async Task StoreAuthState(AuthenticationParameters authParameters)
{
    // Store state with 15-minute expiration
    await _cache.SetStringAsync(
        $"auth_state:{authParameters.State}",
        JsonSerializer.Serialize(stateData),
        new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
        }
    );
}
```

2. **State Validation**: Ensures OAuth callbacks match stored state and haven't expired:
```csharp
public async Task<AuthStateData> ValidateState(string state)
{
    var stateData = JsonSerializer.Deserialize<AuthStateData>(stateJson);
    if (DateTime.UtcNow - stateData.Timestamp > TimeSpan.FromMinutes(15))
        throw new SecurityException("State expired");
}
```

### Key Management Service

The key service manages RSA key pairs for JWT signing and verification:

```csharp
public class KeyService : IKeyService
{
    public RsaSecurityKey PublicKey { get; }
    public RsaSecurityKey PrivateKey { get; }
    
    // Keys are loaded from configuration and imported as RSA parameters
    public KeyService(IConfiguration configuration)
    {
        using (var rsaPublic = RSA.Create())
        {
            rsaPublic.ImportFromPem(config.PublicKey);
            PublicKey = new RsaSecurityKey(rsaPublic.ExportParameters(false));
        }
    }
}
```

### Authentication Service

The authentication service handles OAuth flows and user information retrieval:

1. **OAuth Login Flow**: Builds authorization URLs with proper security parameters:
```csharp
public string BuildLoginUri(AuthenticationParameters parameters)
{
    // Include PKCE challenge and state parameter for security
    var queryParams = new Dictionary<string, string>
    {
        ["state"] = parameters.State,
        ["code_challenge"] = parameters.Challenge,
        ["code_challenge_method"] = "S256"
    };
}
```

2. **Token Exchange**: Securely exchanges authorization codes for tokens:
```csharp
public async Task<TokenResponse> ExchangeCodeForTokens(AuthenticationParameters parameters)
{
    // Include PKCE verifier in token request
    var tokenRequest = new Dictionary<string, string>
    {
        ["code_verifier"] = parameters.ChallengeVerifier,
        ["code"] = parameters.AuthorizationCode
    };
}
```

3. **Claims Mapping**: Standardizes user claims across different identity providers:
```csharp
public async Task<UserInfos> GetUserInfosAsync(AuthenticationParameters parameters)
{
    // Map provider-specific claims to standardized format
    foreach (var (key, value) in userInfoDictionary)
    {
        var destinationClaim = mappings.FirstOrDefault(m => 
            m.Value.ToString() == key).Key;
        if (!string.IsNullOrEmpty(destinationClaim))
        {
            mappedUser.Add(destinationClaim, value);
        }
    }
}
```

### Authentication Flow Integration

When a user initiates external authentication, a carefully orchestrated sequence of security checks and validations occurs:

#### Initial Authentication Request

When a user clicks "Login with Google" (or another provider), the `ExternalLogin` endpoint springs into action:

```csharp
private static async Task<IResult> ExternalLogin(
    HttpContext context,
    string provider,
    AuthConfiguration configuration,
    IAuthService authService,
    ISecurityService securityService)
{
    var authParameters = new AuthenticationParameters(provider);
    await securityService.StoreAuthState(authParameters);
    var loginUri = authService.BuildLoginUri(authParameters);
    return Results.Ok(loginUri);
}
```

This initial step creates a secure foundation for the authentication process by storing a time-limited state token in the distributed cache, while the AuthService constructs a secure authorization URL that includes PKCE protection against interception attacks.

#### Handling the OAuth Callback

The callback handling demonstrates how multiple security services work in concert to validate and process the authentication response:

```csharp
private static async Task<IResult> Callback(
    HttpContext context,
    ISecurityService securityService,
    IAuthService authService,
    ITokenService tokenService,
    /* other dependencies */)
{
    // First security check: Validate the state parameter
    var state = context.GetUriParameterFromHttpContext("state");
    var authStateData = await securityService.ValidateState(state);
    
    // Exchange authorization code securely
    var code = context.GetUriParameterFromHttpContext("code");
    authParameters.AuthorizationCode = code;
    var tokenResponse = await authService.ExchangeCodeForTokens(authParameters);
    
    // Get and standardize user information
    var userInfos = await authService.GetUserInfosAsync(authParameters);
    
    // Generate secure application tokens
    var accessTokenResponse = await tokenService.GetAccessTokenAsync(user);
}
```

This callback process implements multiple layers of security, from state validation to secure code exchange and standardized identity handling.

### Cookie Security Implementation

The final step involves secure cookie handling for the generated tokens:

```csharp
private static void AddCookies(HttpContext context, AccessTokenResponse accessTokenResponse)
{
    var cookieOptions = new CookieOptions
    {
        HttpOnly = false,  // Allows JavaScript access for client-side features
        Secure = true,     // Requires HTTPS
        SameSite = SameSiteMode.Lax,   // Protects against CSRF
        Expires = DateTimeOffset.UtcNow.AddHours(2),
        Domain = isDev ? ".localhost" : ".yourdomain.com",
        Path = "/"
    };
    
    context.Response.Cookies.Append("access_token", accessTokenResponse.AccessToken, cookieOptions);
}
```

The cookie configuration provides several security features to protect authentication tokens.

This comprehensive security implementation ensures that user authentication flows are protected at every step, from initial login to token usage, providing a robust foundation for application security.
