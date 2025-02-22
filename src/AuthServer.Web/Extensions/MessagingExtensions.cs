using AuthServer.Web.Consumer;
using MassTransit;

namespace AuthServer.Web.Extensions;

public static class MessagingExtensions  
{
    public static IServiceCollection AddMessaging(this IServiceCollection services)
    {

        services.AddMassTransit(x =>
        {
            x.AddConsumer<CreateStripeCustomerConsumer>();
    
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ConfigureEndpoints(context);
        
                cfg.UseMessageRetry(r => 
                {
                    r.Incremental(3, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2));
                });
            });
        });
        return services;
    }
}