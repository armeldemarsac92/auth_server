using AuthServer.Contracts.Exceptions;
using Stripe;

namespace AuthServer.Stripe.SDK.Services;

public interface IStripeSetupIntentService
{
    Task<SetupIntent> CreateAsync(SetupIntentCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<SetupIntent> GetAsync(string setupIntentId, SetupIntentGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<SetupIntent> UpdateAsync(string setupIntentId, SetupIntentUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<SetupIntent> CancelAsync(string setupIntentId, SetupIntentCancelOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<SetupIntent> ConfirmAsync(string setupIntentId, SetupIntentConfirmOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}

public class StripeSetupIntentService : IStripeSetupIntentService
{
    private readonly SetupIntentService _setupIntentService;

    public StripeSetupIntentService(SetupIntentService setupIntentService)
    {
        _setupIntentService = setupIntentService;
    }

    public async Task<SetupIntent> CreateAsync(SetupIntentCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        return await _setupIntentService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<SetupIntent> GetAsync(string setupIntentId, SetupIntentGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(setupIntentId))
        {
            throw new BadRequestException(nameof(setupIntentId));
        }

        return await _setupIntentService.GetAsync(setupIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<SetupIntent> UpdateAsync(string setupIntentId, SetupIntentUpdateOptions? options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(setupIntentId))
        {
            throw new BadRequestException(nameof(setupIntentId));
        }

        return await _setupIntentService.UpdateAsync(setupIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<SetupIntent> CancelAsync(string setupIntentId, SetupIntentCancelOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(setupIntentId))
        {
            throw new BadRequestException(nameof(setupIntentId));
        }

        return await _setupIntentService.CancelAsync(setupIntentId, options, requestOptions, cancellationToken);
    }

    public async Task<SetupIntent> ConfirmAsync(string setupIntentId, SetupIntentConfirmOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(setupIntentId))
        {
            throw new BadRequestException(nameof(setupIntentId));
        }

        return await _setupIntentService.ConfirmAsync(setupIntentId, options, requestOptions, cancellationToken);
    }
}