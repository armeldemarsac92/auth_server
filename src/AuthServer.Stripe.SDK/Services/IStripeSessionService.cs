using AuthServer.Contracts.Exceptions;
using Stripe;
using Stripe.Checkout;

namespace AuthServer.Stripe.SDK.Services;

public interface IStripeSessionService
{
    Task<Session> CreateAsync(SessionCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Session> GetAsync(string paymentIntentId, SessionGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Session> UpdateAsync(string paymentIntentId, SessionUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}

public class StripeSessionService : IStripeSessionService
{
    private readonly SessionService _sessionService;

    public StripeSessionService(SessionService sessionService)
    {
        _sessionService = sessionService;
    }

    public async Task<Session> CreateAsync(SessionCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        return await _sessionService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<Session> GetAsync(string paymentIntentId, SessionGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _sessionService.GetAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<Session> UpdateAsync(string paymentIntentId, SessionUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _sessionService.UpdateAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }
    
}