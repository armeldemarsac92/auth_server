using AuthServer.Stripe.SDK.Services;
using Microsoft.Extensions.DependencyInjection;
using Stripe;
using Stripe.Checkout;

namespace AuthServer.Stripe.SDK.DI;

public static class StripeServices
{
    public static IServiceCollection AddStripeServices(this IServiceCollection services, Contracts.Config.StripeConfiguration stripeConfiguration)
    {
        //COnfigure Stripe.net library
        StripeConfiguration.ApiKey = stripeConfiguration.ApiKey;
        services.AddScoped<InvoiceService>();
        services.AddScoped<CustomerService>();
        services.AddScoped<SetupIntentService>();
        services.AddScoped<PaymentMethodService>();
        services.AddScoped<CustomerPaymentMethodService>();
        services.AddScoped<PaymentIntentService>();
        services.AddScoped<ChargeService>();
        services.AddScoped<InvoiceItemService>();
        services.AddScoped<SessionService>();
        
        //Configure Stripe.net library implementations
        services.AddScoped<IStripeInvoiceService, StripeInvoiceService>();
        services.AddScoped<IStripeCustomerService, StripeCustomerService>();
        services.AddScoped<IStripeSetupIntentService, StripeSetupIntentService>();
        services.AddScoped<IStripePaymentMethodService, StripePaymentMethodService>();
        services.AddScoped<IStripeCustomerPaymentMethodService, StripeCustomerPaymentMethodService>();
        services.AddScoped<IStripePaymentIntentService, StripePaymentIntentService>();
        services.AddScoped<IStripeChargeService, StripeChargeService>();
        services.AddScoped<IStripeSessionService, StripeSessionService>();
        
        return services;
    }
}