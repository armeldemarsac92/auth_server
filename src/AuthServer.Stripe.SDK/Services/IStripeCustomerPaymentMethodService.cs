using AuthServer.Contracts.Exceptions;
using Stripe;

namespace AuthServer.Stripe.SDK.Services;

public interface IStripeCustomerPaymentMethodService
{
    Task<PaymentMethod> GetAsync(string parentId, string paymentMethodId, CustomerPaymentMethodGetOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<StripeList<PaymentMethod>> ListAsync(string customerId, CustomerPaymentMethodListOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}

public class StripeCustomerPaymentMethodService : IStripeCustomerPaymentMethodService
{
    private readonly CustomerPaymentMethodService _paymentMethodService;

    public StripeCustomerPaymentMethodService(CustomerPaymentMethodService paymentMethodService)
    {
        _paymentMethodService = paymentMethodService;
    }

    public async Task<PaymentMethod> GetAsync(string parentId, string paymentMethodId, CustomerPaymentMethodGetOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(parentId))
        {
            throw new BadRequestException(nameof(parentId));
        }

        return await _paymentMethodService.GetAsync(parentId, paymentMethodId, options, requestOptions, cancellationToken);
    }

    public async Task<StripeList<PaymentMethod>> ListAsync(string customerId, CustomerPaymentMethodListOptions? options = null,
        RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(customerId))
        {
            throw new BadRequestException(nameof(customerId));
        }
        
        return await _paymentMethodService.ListAsync(customerId, options, requestOptions, cancellationToken);
    }
}