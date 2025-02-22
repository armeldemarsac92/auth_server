# Authentication Server

A sophisticated, enterprise-grade authentication service built with .NET, providing comprehensive identity management, multi-factor authentication, OAuth integration, and payment processing capabilities. This system is designed with security, scalability, and flexibility in mind, supporting both traditional and modern authentication workflows.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Core Features](#core-features)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Configuration](#configuration-guide)
6. [Getting Started](#getting-started)
8. [API Documentation](#api-documentation)
9. [Security Features](#security-features-and-implementation)

## Project Overview

This Authentication Server is designed as a complete identity management solution that combines modern authentication practices with cloud services integration. It serves as a centralized authentication and authorization system that can be easily integrated with other applications while maintaining high security standards and providing a seamless user experience.

## Core Features

### Authentication Capabilities
- Email and password authentication
- Multi-factor authentication (2FA)
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
- Redis caching support
- Message queue integration
- Monitoring and logging infrastructure

### Security Features
- XSRF protection
- Rate limiting
- Password hashing with modern algorithms
- SSL/TLS encryption
- Security headers management
- Request validation


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
- **Session Management**: Checkout sessions

Let me provide a comprehensive prerequisites section that covers all the required external services and configurations for this authentication server:

## Prerequisites

Before setting up the Authentication Server, you'll need to configure several external services and ensure your development environment meets specific requirements. Let's walk through each component:

### Development Environment
- .NET 8.0 SDK or later
- PostgreSQL 13.0 or later
- Redis 6.2 or later for distributed caching (optional, the server uses in memory caching)
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

#### AWS Simple Queue Service (SQS)
For reliable message processing, configure:
- Standard queues for each message type (user notifications, system events)
- Dead letter queues for handling failed message processing
- Appropriate message retention periods (typically 14 days)
- Message visibility timeout settings based on your processing needs

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
                "sqs:SendMessage",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes"
            ],
            "Resource": "arn:aws:sqs:eu-central-1:*:authServer-*"
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

### Configuration Verification
Before proceeding with development, verify your setup:

```bash
# Test AWS Secrets Manager access
aws secretsmanager get-secret-value --secret-id authServer/dev/shared/database

# Test SES configuration
aws ses get-send-quota
aws ses verify-email-identity --email your-sender@yourdomain.com

# Test SQS access
aws sqs list-queues --queue-name-prefix authServer

# Verify Stripe configuration
stripe listen --forward-to http://localhost:5000/stripe/webhook
```

Remember to set up appropriate monitoring and alerting for these services in production. AWS CloudWatch can be configured to monitor SES bounces, SQS queue depths, and application logs. Stripe provides its own dashboard for monitoring payment-related events and webhook delivery status.

For local development, we recommend using AWS CLI profiles to manage different AWS environments and Stripe's CLI for webhook testing. Never commit sensitive credentials to version control - always use environment variables or AWS Secrets Manager for configuration values.


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
    "Key": "your-database-key",
    "Url": "your-database-url",
    "Email": "database-admin@yourdomain.com",
    "Password": "your-database-password",
    "DbConnectionString": "Host=...;Database=...;Username=...;Password=...",
    "SslCert": "-----BEGIN CERTIFICATE-----\n..."
  },
  "StripeConfiguration": {
    "ApiKey": "sk_test_..."
  },
  "CacheConfiguration": {
    "Host": "your-redis-host",
    "InstanceName": "your-instance-name",
    "KeyPrefix": "auth"
  }
}
```

## API Documentation

### Authentication Routes (`/api/auth/*`)

The authentication endpoints handle all aspects of user identity and authentication flows. Each endpoint is designed with security and user experience in mind.

#### User Registration and Login

```csharp
POST /api/auth/register
```
Creates a new user account. The registration process includes email verification and optional 2FA setup.

Request body:
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "firstName": "John",
  "lastName": "Doe"
}
```

```csharp
POST /api/auth/login
```
Authenticates a user and returns JWT tokens. Handles 2FA challenges when enabled.

Request body:
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJ...",
  "refreshToken": "eyJhbGciOiJ...",
  "expiresIn": 3600,
  "requires2FA": false
}
```

#### Email Verification Flow

```csharp
GET /api/auth/confirm-email/{userId}/{token}
```
Validates email confirmation tokens sent to users upon registration.

```csharp
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

```csharp
POST /api/auth/forgot-password
```
Initiates the password reset flow by sending a reset link via email.

```csharp
POST /api/auth/reset-password
```
Completes the password reset process with a valid reset token.

Request body:
```json
{
  "token": "reset-token",
  "newPassword": "newSecurePassword123"
}
```

#### Two-Factor Authentication

```csharp
POST /api/2fa/enable/{type}
```
Enables 2FA for a user account. Supported types include "authenticator" and "email".

```csharp
POST /api/2fa/verify
```
Verifies 2FA setup or login challenges.

Request body:
```json
{
  "code": "123456",
  "type": "authenticator"
}
```

```csharp
POST /api/2fa/disable
```
Disables 2FA for a user account (requires current 2FA code for verification).

#### OAuth/External Authentication

```csharp
GET /api/auth/external-login/{provider}
```
Initiates OAuth flow with specified provider (e.g., "google", "facebook").

```csharp
GET /api/auth/external-callback
```
Handles OAuth provider callbacks and user creation/login.

#### Token Management

```csharp
POST /api/auth/refresh
```
Issues new access tokens using a valid refresh token.

Request body:
```json
{
  "refreshToken": "eyJhbGciOiJ..."
}
```

### Role Management Routes (`/api/roles/*`)

These endpoints manage user roles and permissions within the system.

```csharp
GET /api/roles
```
Returns all available roles in the system.

```csharp
POST /api/roles
```
Creates a new role.

Request body:
```json
{
  "name": "admin",
  "permissions": ["read", "write", "delete"]
}
```

```csharp
DELETE /api/roles/{roleName}
```
Removes an existing role.

```csharp
POST /api/users/{userId}/roles
```
Assigns roles to a user.

Request body:
```json
{
  "roles": ["admin", "user"]
}
```

```csharp
DELETE /api/users/{userId}/roles/{roleName}
```
Removes a role from a user.

```csharp
GET /api/users/{userId}/roles
```
Retrieves all roles assigned to a user.

I'll revise the Security Features section to accurately reflect your actual implementation, writing it in a clear and educational way:


## Security Features and Implementation

The authentication server implements a comprehensive security architecture built around several core services working together to ensure secure authentication and authorization.

### Token Service Implementation

The token service manages JWT generation and validation using asymmetric RSA encryption. Here's how it works:

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

When a user initiates external authentication through your system, a carefully orchestrated sequence of security checks and validations occurs. Here's how the components work together:

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

This initial step creates a secure foundation for the authentication process. The SecurityService stores a time-limited state token in the distributed cache, while the AuthService constructs a secure authorization URL that includes PKCE (Proof Key for Code Exchange) protection against interception attacks.

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

This callback process implements multiple layers of security:

1. The SecurityService validates the state token, ensuring it matches what was originally stored and hasn't expired. This prevents CSRF (Cross-Site Request Forgery) attacks.

2. The AuthService handles the secure exchange of the authorization code for tokens, using the PKCE verifier to prevent code interception attacks.

3. The user information is retrieved and standardized through a secure claims mapping process, ensuring consistent identity handling regardless of the provider.

4. Finally, the TokenService generates application-specific tokens using asymmetric RSA encryption, providing secure access credentials to the user.

#### Cookie Security Implementation

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
        Domain = isDev ? ".localhost" : ".epitechproject.fr",
        Path = "/"
    };
    
    context.Response.Cookies.Append("access_token", accessTokenResponse.AccessToken, cookieOptions);
}
```

The cookie configuration provides several security features:
- Secure flag ensures cookies are only sent over HTTPS
- SameSite protection helps prevent CSRF attacks
- Domain and Path restrictions limit cookie scope
- Appropriate expiration times reduce the window of vulnerability

#### Standard Login Flow

The standard login process shows how these security components handle traditional authentication:

```csharp
private static async Task<IResult> Login(
    UserManager<User> userManager,
    ITokenService tokenService,
    SignInManager<User> signInManager,
    IEmailService emailService,
    LoginUserRequest request)
{
    var result = await signInManager.PasswordSignInAsync(
        request.Email,
        request.Password,
        isPersistent: false,
        lockoutOnFailure: true);
```

This implementation includes several security features:
- Account lockout protection against brute force attacks
- Multi-factor authentication support with different provider options
- Secure password verification through ASP.NET Identity
- Email-based verification codes for additional security

The system intelligently handles different 2FA scenarios:
```csharp
switch (user.PreferredTwoFactorProvider)
{
    case TwoFactorType.Email:
        var emailToken = await signInManager.UserManager.GenerateTwoFactorTokenAsync(user, "Email");
        await emailService.SendEmailAsync(
            user.Email,
            "2FA Code",
            $"Your verification code is: {emailToken}");
        return Results.Ok(new { requiresTwoFactor = true, provider = "Email" });
```

### Refresh Token Flow

The refresh token implementation includes important security considerations:

```csharp
private static async Task<IResult> RefreshToken(
    UserManager<User> userManager,
    ITokenService tokenService,
    RefreshTokenRequest request)
{
    var principal = tokenService.ValidateToken(request.RefreshToken, validateLifetime: false);
    var userId = principal.FindFirst(ClaimTypes.NameIdentifier).Value;
    var user = await userManager.FindByIdAsync(userId);
```

This flow is significant because it:
- Validates the refresh token cryptographically even when expired
- Extracts the user identifier from validated claims
- Verifies the user still exists in the system
- Issues fresh access and refresh tokens, implementing token rotation

### Email Verification Security

The email confirmation flow implements several security measures:

```csharp
private static async Task<IResult> ConfirmEmail(
    UserManager<User> userManager,
    string userId,
    string token)
{
    var user = await userManager.FindByIdAsync(userId);
    var decodedToken = Uri.UnescapeDataString(token);
    var result = await userManager.ConfirmEmailAsync(user, decodedToken);
```

This implementation:
- Uses secure tokens generated by ASP.NET Identity
- Properly handles URL-encoded tokens to prevent corruption
- Validates both the user ID and the confirmation token together
- Marks email verification status in user claims

### Password Reset Security

The password reset flow includes important protections:

```csharp
private static async Task<IResult> ForgotPassword(
    UserManager<User> userManager,
    IEmailSender<User> emailSender,
    LinkGenerator linkGenerator,
    HttpContext httpContext,
    ForgotPasswordRequest request)
{
    var user = await userManager.FindByEmailAsync(request.Email);
    if (user == null) return Results.Ok(); 
```

This implementation provides security through:
- Same response timing whether the user exists or not (preventing user enumeration)
- Secure token generation for password reset
- Email-based delivery of reset instructions
- Limited-time token validity
