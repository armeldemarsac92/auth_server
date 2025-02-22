using Stripe;

namespace AuthServer.Stripe.SDK.Services;
public interface IStripeChargeService
{
    Task<Charge> GetAsync(string id, ChargeGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Charge> CreateAsync(ChargeCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Charge> UpdateAsync(string id, ChargeUpdateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}
public class StripeChargeService : IStripeChargeService
{
    private readonly ChargeService _chargeService;

    public StripeChargeService(ChargeService chargeService)
    {
        _chargeService = chargeService;
    }
    
    
    public async Task<Charge> GetAsync(
        string id, 
        ChargeGetOptions? options = null, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return await _chargeService.GetAsync(id, options, requestOptions, cancellationToken);
    }

    public async Task<Charge> CreateAsync(
        ChargeCreateOptions options, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return await _chargeService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<Charge> UpdateAsync(
        string id, 
        ChargeUpdateOptions options, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(options);
        return await _chargeService.UpdateAsync(id, options, requestOptions, cancellationToken);
    }
}
    
