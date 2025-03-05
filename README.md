# AuthServer - .NET 8 Authentication & Authorization Service

This repository contains a robust, feature-rich authentication and authorization service built with .NET 8. It provides a complete solution for user identity management with support for JWT tokens, two-factor authentication, and OAuth integration with external providers.

## Architecture Overview

The solution is organized into three main projects:

1. **AuthServer.Web**: The main ASP.NET Core web application that hosts the API endpoints and orchestrates all the authentication flows.

2. **AuthServer.Contracts**: Contains shared models, interfaces, database entities, and other contracts used across the solution.

3. **AuthServer.AWS.SDK**: AWS integration components for CloudWatch logging, Secrets Manager configuration, and Simple Email Service (SES) for sending verification emails.

The architecture follows clean code principles with:
- Clear separation of concerns
- Dependency injection throughout
- Interface-based design
- Middleware pipeline for cross-cutting concerns
- Exception handling with appropriate HTTP status codes

## Core Features

### User Authentication

- **JWT-based authentication**: Secure token generation with RS256 signing (public/private key)
- **Token refresh mechanism**: Long-lived refresh tokens with short-lived access tokens
- **Password-based authentication**: Standard username/password authentication with Identity framework

### Two-Factor Authentication

- Email-based 2FA with verification codes
- SMS-based 2FA capability (configurable)
- Customizable 2FA flow with preferred provider selection

### OAuth/External Authentication

- Google OAuth 2.0 integration
- Facebook OAuth integration
- Extensible architecture for adding other providers
- PKCE flow for enhanced security
- State validation to prevent CSRF attacks

### User Management

- User registration with email verification
- User profile updates
- Role-based authorization
- Admin capabilities for role management
- Custom user claims for enhanced authorization

### Security Features

- HTTPS enforcement
- CORS configuration
- Anti-forgery protection
- Secure cookie policies
- Input validation
- Rate limiting
- Exception handling with security in mind

### AWS Integration

- CloudWatch logging for centralized log management
- Secrets Manager for secure configuration
- SES for transactional emails
- Environment-based configuration

## Authentication Flows

### Registration Flow

1. User provides email (via `/api/auth/register` endpoint)
2. System creates user in database with the `User` role
3. System generates 2FA verification code
4. System sends verification code via email using AWS SES
5. System returns `requiresTwoFactor: true` response
6. User provides the verification code to complete registration
7. User is now registered and can log in

### Login Flow

1. User provides email and password (via `/api/auth/login` endpoint)
2. System validates credentials
3. System may require 2FA (sends code via preferred method)
4. User provides 2FA code
5. System validates the code and confirms the user if needed
6. System generates JWT access and refresh tokens
7. Tokens are returned to the user

### External Provider Flow (OAuth)

1. User initiates OAuth flow by visiting `/api/auth/external-login/{provider}`
2. System generates state and PKCE challenge for security
3. System stores authentication parameters in distributed cache
4. User is redirected to provider's authorization endpoint
5. User authenticates with the provider and grants permissions
6. Provider redirects back to `/api/auth/external-callback` with authorization code
7. System exchanges code for tokens with provider
8. System validates state to prevent CSRF attacks
9. System retrieves user info from provider
10. System creates or updates user with provider information
11. System generates JWT tokens and sets cookies
12. User is redirected to frontend application

### Token Refresh Flow

1. User sends refresh token to `/api/auth/refresh` endpoint
2. System validates the refresh token
3. System generates new access and refresh tokens
4. New tokens are returned to the user

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate a user
- `POST /api/auth/update` - Update user profile
- `POST /api/auth/refresh` - Refresh authentication tokens
- `POST /api/auth/resend-code` - Resend 2FA verification code
- `GET /api/auth/external-login/{provider}` - Initiate OAuth flow
- `GET /api/auth/external-callback` - OAuth callback endpoint
- `GET /api/auth/healthcheck` - Service health check

### Role Management Endpoints

- `GET /api/roles` - Get all roles
- `POST /api/roles` - Create a new role
- `DELETE /api/roles/{roleName}` - Delete a role
- `POST /api/users/{userId}/roles` - Add user to role
- `DELETE /api/users/{userId}/roles/{roleName}` - Remove user from role
- `GET /api/users/{userId}/roles` - Get user roles

## Database Schema

The service uses Entity Framework Core with PostgreSQL and implements the ASP.NET Core Identity schema with custom extensions:

- **AspNetUsers** - User data with custom fields:
  - PreferredTwoFactorProvider
  - FirstName, LastName
  - ProfilePicture
  - CreatedAt, UpdatedAt

- **AspNetRoles** - Role definitions
- **AspNetUserRoles** - User-role relationships
- **AspNetUserClaims** - User claims
- **AspNetUserLogins** - External login associations
- **AspNetUserTokens** - User tokens

## AWS Integration Setup

### AWS Secrets Manager Integration

The AuthServer uses AWS Secrets Manager to securely store and retrieve sensitive configuration such as database credentials, JWT signing keys, and OAuth client secrets. Here's how to set it up:

### 1. AWS Secrets Structure

The application expects secrets to be organized in the following structure in AWS Secrets Manager:

```
{projectname}/{environment}/shared/{secret-type}
```

Where:
- `{environment}` is your environment name (e.g., Development, Staging, Production)
- `{projectname}` is the name of your project
- `{secret-type}` is one of the defined secret types: database, auth

For example:
- `myproject/Development/shared/database`
- `myproject/Production/shared/auth`

### 2. Required Secret Configuration

#### Database Secret (required)
```json
{
  "database": {
    "Key": "your-database-key",
    "Url": "your-database-url",
    "Email": "your-database-admin-email",
    "Password": "your-database-password",
    "DbConnectionString": "Host=your-host;Database=your-db;Username=your-user;Password=your-password;",
    "SslCert": "your-ssl-cert-if-needed"
  }
}
```

#### Auth Secret (required)
```json
{
  "auth": {
    "CorsAllowOrigin": "https://your-frontend-origin.com",
    "JwtIssuer": "https://your-auth-server.com",
    "JwtAudience": "your-audience",
    "PrivateKey": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    "PublicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "SourceEmail": "noreply@yourdomain.com",
    "SmtpUsername": "your-smtp-username",
    "SmtpPassword": "your-smtp-password",
    "IdentityProviders": [
      {
        "Name": "google",
        "ClientId": "your-google-client-id",
        "ClientSecret": "your-google-client-secret",
        "RedirectUri": "https://your-auth-server.com/api/auth/external-callback",
        "Scope": "openid email profile",
        "GrantType": "authorization_code",
        "ResponseType": "code",
        "CodeEndpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "TokenEndpoint": "https://oauth2.googleapis.com/token",
        "UserInfoEndpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "FrontEndRedirectUri": "https://your-frontend.com/auth/callback",
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
        "Name": "facebook",
        "ClientId": "your-facebook-client-id",
        "ClientSecret": "your-facebook-client-secret",
        "RedirectUri": "https://your-auth-server.com/api/auth/external-callback",
        "Scope": "email public_profile",
        "GrantType": "authorization_code",
        "ResponseType": "code",
        "CodeEndpoint": "https://www.facebook.com/v16.0/dialog/oauth",
        "TokenEndpoint": "https://graph.facebook.com/v16.0/oauth/access_token",
        "UserInfoEndpoint": "https://graph.facebook.com/v16.0/me",
        "FrontEndRedirectUri": "https://your-frontend.com/auth/callback",
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
  }
}
```

### 3. Setting Up AWS Credentials

The application uses the AWS SDK's default credential provider chain, which means it will look for credentials in the following order:

1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. AWS credentials file (~/.aws/credentials)
3. Instance profile credentials (if running on EC2 or ECS)

For local development, you can set up the AWS CLI and run `aws configure` to create your credentials file.

### 4. Project Configuration

The integration with Secrets Manager is set up in the `Program.cs` file using:

```csharp
builder.AddAwsConfiguration(SecretType.Database, SecretType.Auth, SecretType.Stripe);
```

This extension method is defined in `AuthServer.AWS.SDK.SecretsManager.ConfigurationExtensions` and it does the following:

1. Retrieves the environment name from `ASPNETCORE_ENVIRONMENT`
2. Configures AWS Secrets Manager as a configuration source
3. Sets up a key generator to map secret paths to configuration keys
4. Filters secrets based on the specified secret types
5. Adds the retrieved configuration to appropriate services

### AWS CloudWatch Integration

The application integrates with AWS CloudWatch for centralized logging. Here's how to set it up:

### 1. CloudWatch Configuration

In your `appsettings.json` (and environment-specific variants), configure the CloudWatch settings:

```json
{
  "AWS": {
    "Region": "eu-central-1",
    "CloudWatch": {
      "LogGroupName": "your-app-name-auth"
    }
  }
}
```

The actual CloudWatch integration is configured in `AuthServer.AWS.SDK.CloudWatch.CloudWatchExtension`. It sets up Serilog to:

1. Read log settings from configuration
2. Enrich logs with context information
3. Write logs to both the console and CloudWatch
4. Create log groups and streams automatically

### 2. Log Structure

The application creates a log group with the name pattern:
```
{configuration["AWS:CloudWatch:LogGroupName"]}-{environment}
```

For example, if your configuration specifies `LogGroupName` as `my-app-auth` and your environment is `Production`, the log group will be `my-app-auth-Production`.

### AWS Simple Email Service (SES) Integration

The application uses AWS SES to send verification codes and other emails. Here's how to set it up:

### 1. SES Configuration

The SES integration is set up in `AuthServer.AWS.SDK.SES.AwsSesEmailService` and relies on the Auth configuration:

```json
{
  "auth": {
    "SourceEmail": "noreply@yourdomain.com"
    // ...other auth settings
  }
}
```

### 2. Verifying Email Domains/Addresses

Before you can send emails with SES:

1. Verify your domain or email address in the SES console
2. If your account is in the SES sandbox, you must also verify recipient email addresses
3. For production, request to move out of the SES sandbox

### 3. Email Templates

The application has basic HTML templates for:
- Verification code emails
- Generic message emails

You can customize these in the `AwsSesEmailService.cs` file.

## JWT Key Pair Generation

For JWT authentication, you need to generate an RSA key pair. Here's how to do it using OpenSSL:

```bash
# Generate a private key
openssl genrsa -out private.pem 2048

# Extract the public key from the private key
openssl rsa -in private.pem -pubout -out public.pem
```

Store these keys in AWS Secrets Manager as part of your Auth configuration, with proper line breaks preserved using `\n`:

```json
{
  "auth": {
    "PrivateKey": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    "PublicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    // ...other auth settings
  }
}
```

## Deployment

The repository includes a Dockerfile for containerized deployment. The application is designed to work well with:

- AWS ECS (Elastic Container Service)
- AWS EKS (Elastic Kubernetes Service)
- AWS App Runner
- Amazon EC2 instances
- Any container orchestration platform

### Building the Docker Image

```bash
docker build -t authserver:latest .
```

### Running the Container

```bash
docker run -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e AWS_ACCESS_KEY_ID=your-access-key \
  -e AWS_SECRET_ACCESS_KEY=your-secret-key \
  -e AWS_REGION=eu-central-1 \
  authserver:latest
```

For production deployments, use IAM roles instead of hardcoded AWS credentials.

## Getting Started for Development

### Prerequisites

- .NET 8 SDK
- PostgreSQL database
- AWS account with appropriate permissions
- AWS CLI configured locally

### Local Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/authserver.git
   cd authserver
   ```

2. Set the required environment variables:
   ```bash
   export PROJECT_NAME=myproject
   export ASPNETCORE_ENVIRONMENT=Development
   ```

3. Set up your AWS configuration:
   ```bash
   aws configure
   ```

4. Restore dependencies and build:
   ```bash
   dotnet restore
   dotnet build
   ```

5. Run database migrations:
   ```bash
   cd src/AuthServer.Web
   dotnet ef database update
   ```

6. Run the application:
   ```bash
   dotnet run
   ```

7. Access the Swagger documentation at `https://localhost:7058/swagger`

## Core Components and Services

Let me go into more depth on some of the core services and how they interact with each other:

### UserService

The `UserService` is the central service for user management. It handles:

- User registration
- User authentication
- User profile updates
- Two-factor authentication workflows
- External login provisioning

Key interactions:
- Works with `UserManager<User>` for identity operations
- Uses `IEmailService` to send verification codes
- Uses `ITwoFaService` for 2FA operations
- Uses `ITokenService` for JWT generation
- Uses `IAuthService` for OAuth integration

### AuthService

The `AuthService` handles external authentication flows. It:

- Initiates OAuth flows with providers
- Validates state parameters
- Exchanges authorization codes for tokens
- Retrieves user information from providers
- Maps provider-specific user data to standardized formats

Key interactions:
- Uses `ISecurityService` for state management
- Uses HTTP clients to communicate with OAuth providers
- Returns standardized user information to `UserService`

### TokenService

The `TokenService` manages JWT creation and validation. It:

- Generates JWT access tokens
- Generates refresh tokens
- Validates and refreshes tokens
- Creates appropriate claims for users

Key interactions:
- Uses `IKeyService` for cryptographic operations
- Works with `UserManager<User>` to retrieve user details
- Creates security tokens with user claims and roles

### Security Service

The `SecurityService` handles security-related operations:

- Generates and validates state parameters for OAuth
- Creates and validates PKCE challenges
- Stores authentication state in distributed cache
- Validates ID tokens from providers

Key interactions:
- Uses `IDistributedCache` for temporary state storage
- Implements security best practices for OAuth flows

### AWS Integration Services

- `AwsSesEmailService`: Handles email delivery via AWS SES
- `CloudWatchExtension`: Configures Serilog for AWS CloudWatch
- `ConfigurationExtensions`: Sets up AWS Secrets Manager for configuration

These services provide a seamless integration with AWS services while abstracting the complexity from the rest of the application.