using AuthServer.Contracts.Database;
using AuthServer.Stripe.SDK.Services;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Stripe;

namespace AuthServer.Web.Consumer;

public class CreateStripeCustomerConsumer : IConsumer<User>
{
    private readonly IStripeCustomerService _stripeCustomerService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<CreateStripeCustomerConsumer> _logger;

    public CreateStripeCustomerConsumer(
        IStripeCustomerService stripeCustomerService,
        UserManager<User> userManager,
        ILogger<CreateStripeCustomerConsumer> logger)
    {
        _stripeCustomerService = stripeCustomerService;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<User> context)
    {
        var message = context.Message;
        
        try
        {
            _logger.LogInformation("Creating Stripe customer for user {UserId}", message.Id);
            
            var stripeCustomer = await _stripeCustomerService.CreateAsync(new CustomerCreateOptions
            {
                Email = message.Email,
                Name = $"{message.FirstName} {message.LastName}"
            });
            
            _logger.LogInformation("Created Stripe customer for user {UserId}: {CustomerId}", message.Id, stripeCustomer.Id);
            var user = await _userManager.FindByIdAsync(message.Id);
            if (user != null)
            {
                user.StripeCustomerId = stripeCustomer.Id;
                await _userManager.UpdateAsync(user);
                _logger.LogInformation("Updated user {UserId} with Stripe customer ID {CustomerId}", message.Id, stripeCustomer.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create Stripe customer for user {UserId}", message.Id);
            throw; 
        }
    }
}