using AuthServer.Contracts.Exceptions;
using Stripe;

namespace AuthServer.Stripe.SDK.Services;

public interface IStripeCustomerService
{
    Task<Customer> CreateAsync(CustomerCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Customer> GetAsync(string customerId, CustomerGetOptions? options, RequestOptions? requestOptions = null,CancellationToken cancellationToken = default);
    Task<Customer> UpdateAsync(string customerId, CustomerUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Customer> DeleteAsync(string customerId, CustomerDeleteOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}

public class StripeCustomerService : IStripeCustomerService
{
    private readonly CustomerService _customerService;

    public StripeCustomerService(CustomerService customerService)
    {
        _customerService = customerService;
    }

    public async Task<Customer> CreateAsync(CustomerCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        return await _customerService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<Customer> GetAsync(string customerId, CustomerGetOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(customerId))
        {
            throw new BadRequestException(nameof(customerId));
        }
        
        return await _customerService.GetAsync(customerId, options, requestOptions, cancellationToken);
    }

    public async Task<Customer> UpdateAsync(string customerId, CustomerUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(customerId))
        {
            throw new BadRequestException(nameof(customerId));
        }

        return await _customerService.UpdateAsync(customerId, options, requestOptions, cancellationToken);
    }

    public async Task<Customer> DeleteAsync(string customerId, CustomerDeleteOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(customerId))
        {
            throw new BadRequestException(nameof(customerId));
        }

        return await _customerService.DeleteAsync(customerId, options, requestOptions, cancellationToken);
    }
}