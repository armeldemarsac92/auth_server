using AuthServer.Contracts.Exceptions;
using Stripe;

namespace AuthServer.Stripe.SDK.Services;

public interface IStripePaymentIntentService
{
    Task<PaymentIntent> CreateAsync(PaymentIntentCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<PaymentIntent> GetAsync(string paymentIntentId, PaymentIntentGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<PaymentIntent> UpdateAsync(string paymentIntentId, PaymentIntentUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<PaymentIntent> CancelAsync(string paymentIntentId, PaymentIntentCancelOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<PaymentIntent> ConfirmAsync(string paymentIntentId, PaymentIntentConfirmOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}

public class StripePaymentIntentService : IStripePaymentIntentService
{
    private readonly PaymentIntentService _paymentIntentService;

    public StripePaymentIntentService(PaymentIntentService paymentIntentService)
    {
        _paymentIntentService = paymentIntentService;
    }

    public async Task<PaymentIntent> CreateAsync(PaymentIntentCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        return await _paymentIntentService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<PaymentIntent> GetAsync(string paymentIntentId, PaymentIntentGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _paymentIntentService.GetAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<PaymentIntent> UpdateAsync(string paymentIntentId, PaymentIntentUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _paymentIntentService.UpdateAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<PaymentIntent> CancelAsync(string paymentIntentId, PaymentIntentCancelOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _paymentIntentService.CancelAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<PaymentIntent> ConfirmAsync(string paymentIntentId, PaymentIntentConfirmOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(paymentIntentId))
        {
            throw new BadRequestException(nameof(paymentIntentId));
        }

        return await _paymentIntentService.ConfirmAsync(paymentIntentId, options, requestOptions, cancellationToken);
    }
}