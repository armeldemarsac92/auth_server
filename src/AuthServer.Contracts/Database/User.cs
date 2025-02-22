using System.ComponentModel.DataAnnotations;
using AuthServer.Contracts.Auth;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Contracts.Database;

public class User : IdentityUser
{
    public TwoFactorType? PreferredTwoFactorProvider { get; set; }
    
    [StringLength(50)]
    public string? StripeCustomerId { get; set; }
    
    [StringLength(50)]
    public required string FirstName { get; set; }
    
    [StringLength(50)]
    public required string LastName { get; set; }    
    
    [StringLength(255)]
    public string? ProfilePicture { get; set; }
    
    public DateTime? UpdatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CreatedAt { get; set; }
}