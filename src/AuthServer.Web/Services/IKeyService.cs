using System.Security.Cryptography;
using AuthServer.Contracts.Config;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Web.Services;

public interface IKeyService
{
    public RsaSecurityKey PublicKey { get; }
    public RsaSecurityKey PrivateKey { get; }
}

public class KeyService : IKeyService
{
    public RsaSecurityKey PublicKey { get; }
    public RsaSecurityKey PrivateKey { get; }
   
    public KeyService(IConfiguration configuration)
    {
        var config = configuration.GetSection("auth").Get<AuthConfiguration>()
                     ?? throw new InvalidOperationException("Auth configuration not found");

        using (var rsaPublic = RSA.Create())
        {
            rsaPublic.ImportFromPem(config.PublicKey);
            PublicKey = new RsaSecurityKey(rsaPublic.ExportParameters(false));
        }
       
        using (var rsaPrivate = RSA.Create())
        {
            rsaPrivate.ImportFromPem(config.PrivateKey);
            PrivateKey = new RsaSecurityKey(rsaPrivate.ExportParameters(true));
        }
    }
}
