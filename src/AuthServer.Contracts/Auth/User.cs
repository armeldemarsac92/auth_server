using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Contracts.Auth;

public class ApplicationUser : IdentityUser
{
    [JsonPropertyName("id")]
    public override string Id { get; set; } = default!;
    
    [JsonPropertyName("userName")]
    public override string? UserName { get; set; }  
    
    [JsonPropertyName("normalizedUserName")]
    public override string? NormalizedUserName { get; set; } 
    
    [JsonPropertyName("email")]
    public override string? Email { get; set; } 
    
    [JsonPropertyName("normalizedEmail")]
    public override string? NormalizedEmail { get; set; }  
    
    [JsonPropertyName("emailConfirmed")]  
    public override bool EmailConfirmed { get; set; }
    
    [JsonPropertyName("passwordHash")]
    public override string? PasswordHash { get; set; } 
    
    [JsonPropertyName("securityStamp")]
    public override string? SecurityStamp { get; set; }  
    
    [JsonPropertyName("concurrencyStamp")]
    public override string? ConcurrencyStamp { get; set; }  
    
    [JsonPropertyName("phoneNumber")]
    public override string? PhoneNumber { get; set; }  
    
    [JsonPropertyName("phoneNumberConfirmed")]
    public override bool PhoneNumberConfirmed { get; set; }
    
    [JsonPropertyName("twoFactorEnabled")]
    public override bool TwoFactorEnabled { get; set; }
    
    [JsonPropertyName("lockoutEnd")]
    public override DateTimeOffset? LockoutEnd { get; set; }
    
    [JsonPropertyName("lockoutEnabled")]
    public override bool LockoutEnabled { get; set; }
    
    [JsonPropertyName("accessFailedCount")]
    public override int AccessFailedCount { get; set; }

    public ApplicationUser()
    {
        // Initialize required non-nullable fields
        Id = Guid.NewGuid().ToString();
        ConcurrencyStamp = Guid.NewGuid().ToString();
        SecurityStamp = Guid.NewGuid().ToString();
    }
}