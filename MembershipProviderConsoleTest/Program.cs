using CustomMembershipProvider.Core.Interfaces;
using CustomMembershipProvider.Core.Providers;
using CustomMembershipProvider.Core.Utilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MembershipProviderConsoleTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Build Configuration
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            // Set up dependency injection
            var serviceProvider = new ServiceCollection()
                .AddSingleton<IConfiguration>(configuration)
                .AddDataProtection()
                .Services  // Chain back to IServiceCollection to continue adding services
                .AddSingleton<IPasswordUtility, PasswordUtility>()
                .AddSingleton<IMembershipDataAccess, MembershipDataAccess>()
                .AddSingleton<ICustomSqlMembershipProvider, CustomSqlMembershipProvider>()
                .BuildServiceProvider();

            // Get the membership provider
            var provider = serviceProvider.GetService<ICustomSqlMembershipProvider>();

            // Create an instance of the test class
            var membershipTests = new MembershipProviderTests(provider);

            // Run tests
            membershipTests.TestDeleteUser("newuser");

            membershipTests.TestUserLogin();
            membershipTests.TestUserCreation();
            membershipTests.TestUserLogin();

            membershipTests.TestGetUserByUsername("141");
            membershipTests.TestGetUserByUsername("newuser");

            membershipTests.TestChangePassword("141", "0A5S*sO6", "NewPassword123!");

            membershipTests.TestPasswordReset("newuser");

            membershipTests.TestUnlockUser("141");

            membershipTests.TestGetUserById(new Guid("8203bf05-aaf8-4bf4-a5ca-ffe09e9b33c0"));

            membershipTests.TestFindUsersByEmail("newuser@example.com");

            membershipTests.TestDeleteUser("newuser");

            membershipTests.TestGetAllUsers();

            membershipTests.TestGetNumberOfUsersOnline();
        }
    }
}
