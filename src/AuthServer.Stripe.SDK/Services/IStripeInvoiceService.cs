using Stripe;

namespace AuthServer.Stripe.SDK.Services;
public interface IStripeInvoiceService
{
    Task<Invoice> GetAsync(string id, InvoiceGetOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Invoice> CreateAsync(InvoiceCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<InvoiceItem> CreateItemAsync(InvoiceItemCreateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Invoice> PayAsync(string id, InvoicePayOptions options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Invoice> UpdateAsync(string id, InvoiceUpdateOptions options, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
    Task<Invoice> DeleteAsync(string id, InvoiceDeleteOptions? options = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default);
}
public class StripeInvoiceService : IStripeInvoiceService
{
    private readonly InvoiceService _invoiceService;
    private readonly InvoiceItemService _invoiceItemService;

    public StripeInvoiceService(InvoiceService invoiceService, 
        InvoiceItemService invoiceItemService)
    {
        _invoiceService = invoiceService;
        _invoiceItemService = invoiceItemService;
    }
    
    
    public async Task<Invoice> GetAsync(
        string id, 
        InvoiceGetOptions? options = null, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return await _invoiceService.GetAsync(id, options, requestOptions, cancellationToken);
    }

    public async Task<Invoice> CreateAsync(
        InvoiceCreateOptions options, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return await _invoiceService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<InvoiceItem> CreateItemAsync(InvoiceItemCreateOptions options, RequestOptions? requestOptions = null,
        CancellationToken cancellationToken = default)
    {
        return await _invoiceItemService.CreateAsync(options, requestOptions, cancellationToken);
    }

    public async Task<Invoice> PayAsync(string id, InvoicePayOptions options = null, RequestOptions? requestOptions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return await _invoiceService.PayAsync(id, options, requestOptions, cancellationToken);
    }

    public async Task<Invoice> UpdateAsync(
        string id, 
        InvoiceUpdateOptions options, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(options);
        return await _invoiceService.UpdateAsync(id, options, requestOptions, cancellationToken);
    }

    public async Task<Invoice> DeleteAsync(
        string id, 
        InvoiceDeleteOptions? options = null, 
        RequestOptions? requestOptions = null, 
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return await _invoiceService.DeleteAsync(id, options, requestOptions, cancellationToken);
    }
}
    
