using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthServer.Contracts.Config;
using AuthServer.Contracts.Database;
using AuthServer.Contracts.Exceptions;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Web.Services;

public interface ITokenService
{
    Task<AccessTokenResponse> GetAccessTokenAsync(User user);
    Task<AccessTokenResponse> RefreshTokenAsync(string refreshToken);
    ClaimsPrincipal ValidateToken(string token, bool validateLifetime = true);
}

public class TokenService : ITokenService
{
    private readonly AuthConfiguration _configuration;
    private readonly UserManager<User> _userManager;
    private readonly TokenValidationParameters _tokenValidationParams;
    private readonly IKeyService _keyService;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IConfiguration configuration, UserManager<User> userManager, ILogger<TokenService> logger, IKeyService keyService)
    {
        _userManager = userManager;
        _logger = logger;
        _keyService = keyService;
        _configuration = configuration.GetSection("auth").Get<AuthConfiguration>() 
                         ?? throw new InvalidOperationException("Auth configuration not found");
        
        _tokenValidationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keyService.PublicKey,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = _configuration.JwtIssuer,
            ValidAudience = _configuration.JwtAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    }

    public async Task<AccessTokenResponse> GetAccessTokenAsync(User user)
    {
        try
        {
            _logger.LogInformation("Generating access token for user: {Email}", user.Email);
            var tokenExpiration = TimeSpan.FromMinutes(60);
            var accessToken = await GenerateToken(user, tokenExpiration);
            var refreshToken = await GenerateToken(user, TimeSpan.FromDays(1));
        
            return new AccessTokenResponse()
            { 
                AccessToken = accessToken, 
                RefreshToken = refreshToken, 
                ExpiresIn = (int)tokenExpiration.TotalSeconds 
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate tokens for user: {Email}", user.Email);
            throw;
        }
    }

    public async Task<AccessTokenResponse> RefreshTokenAsync(string refreshToken)
    {
        _logger.LogInformation("Validating refresh token");
        var claims = ValidateToken(refreshToken);
        _logger.LogInformation("Valid refresh token, getting user details");
        var user = await _userManager.GetUserAsync(claims);
        CheckUser(user);
        return await GetAccessTokenAsync(user);
    }

    public ClaimsPrincipal ValidateToken(string token, bool validateLifetime = true)
    {
        _tokenValidationParams.ValidateLifetime = validateLifetime;
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var principal = tokenHandler.ValidateToken(token, _tokenValidationParams, out _);
        return principal;
    }

    private async Task<string> GenerateToken(User user, TimeSpan expiration)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    
            new(ClaimTypes.Name, user.UserName),
            new(JwtRegisteredClaimNames.GivenName, user.FirstName ?? string.Empty),
            new(JwtRegisteredClaimNames.FamilyName, user.LastName ?? string.Empty),
            new("email_verified", user.EmailConfirmed.ToString().ToLower()),
            new("picture", user.ProfilePicture ?? string.Empty),
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var token = new JwtSecurityToken(
            issuer: _configuration.JwtIssuer,
            audience: _configuration.JwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.Add(expiration),
            signingCredentials: new SigningCredentials(
                _keyService.PrivateKey,
                SecurityAlgorithms.RsaSha256)
        );

        return tokenHandler.WriteToken(token);
    }
    
    private void CheckUser(User? user)
    {
        if (user == null) throw new BadRequestException("User not found");
        _logger.LogInformation("User {UserId} found.", user.Id);
        if (user.LockoutEnabled) throw new BadRequestException($"User {user.Id} is locked out.");
    }
}