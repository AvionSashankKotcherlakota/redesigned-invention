using CustomMembershipProvider.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MembershipProviderConsoleTest
{
    internal class MembershipProviderTests
    {
        private readonly ICustomSqlMembershipProvider _provider;

        // Constructor: Pass the membership provider as a dependency
        public MembershipProviderTests(ICustomSqlMembershipProvider provider)
        {
            _provider = provider;
        }

        // 1. Test for user creation
        public void TestUserCreation()
        {
            Console.WriteLine("Running TestUserCreation...");

            var username = "newuser";
            var password = "NewPassword123!";
            var email = "newuser@example.com";

            var user = _provider.CreateUser(username, password, email, null, null, true, null, out var status);

            Console.WriteLine($"User creation status: {status}");
            Console.WriteLine($"User created: {user?.UserName}");
        }

        // 2. Test user validation (login)
        public void TestUserLogin()
        {
            Console.WriteLine("Running TestUserLogin...");

            // Test with provided usernames and passwords from the test database
            var users = new (string username, string password)[]
            {
            ("141", "0A5S*sO6"),
            ("142", "7H3ot$@8"),
            ("147", "*@3^wt8C"),
            ("160", "i$GnDE*0"),
            ("177", "@0S#^5Br"),
            ("178", "z$2!Azp!"),
            ("179", "AIdum!i4"),
            ("180", "1B5Oe#n8"),
            ("183", "$^Pw0!FS"),
            ("newuser", "NewPassword123!")
            };

            foreach (var (username, password) in users) {
                var isValid = _provider.ValidateUser(username, password);
                Console.WriteLine($"Login for {username}: {isValid}");
            }
        }

        // 3. Test password reset
        public void TestPasswordReset(string username)
        {
            Console.WriteLine("Running TestPasswordReset...");

            var newPassword = _provider.ResetPassword(username, null);
            Console.WriteLine($"Password reset for {username}. New password: {newPassword}");
        }

        // 4. Test change password
        public void TestChangePassword(string username, string oldPassword, string newPassword)
        {
            Console.WriteLine("Running TestChangePassword...");

            var isChanged = _provider.ChangePassword(username, oldPassword, newPassword);
            Console.WriteLine($"Password change for {username}: {isChanged}");
        }

        // 5. Test unlock user
        public void TestUnlockUser(string username)
        {
            Console.WriteLine("Running TestUnlockUser...");

            var isUnlocked = _provider.UnlockUser(username);
            Console.WriteLine($"User {username} unlocked: {isUnlocked}");
        }

        // 6. Test get user by username
        public void TestGetUserByUsername(string username)
        {
            Console.WriteLine("Running TestGetUserByUsername...");

            var user = _provider.GetUser(username, true);
            Console.WriteLine($"User found: {user?.UserName}, Email: {user?.Email}");
        }

        // 7. Test get user by user ID
        public void TestGetUserById(Guid userId)
        {
            Console.WriteLine("Running TestGetUserById...");

            var user = _provider.GetUser(userId, true);
            Console.WriteLine($"User found by ID: {user?.UserName}, Email: {user?.Email}");
        }

        // 8. Test delete user
        public void TestDeleteUser(string username)
        {
            Console.WriteLine("Running TestDeleteUser...");

            var isDeleted = _provider.DeleteUser(username, true);
            Console.WriteLine($"User {username} deleted: {isDeleted}");
        }

        // 9. Test find users by email
        public void TestFindUsersByEmail(string email)
        {
            Console.WriteLine("Running TestFindUsersByEmail...");

            var users = _provider.FindUsersByEmail(email, 0, 10, out int totalRecords);
            Console.WriteLine($"Total users found with email {email}: {totalRecords}");
        }

        // 10. Test get all users
        public void TestGetAllUsers()
        {
            Console.WriteLine("Running TestGetAllUsers...");

            var users = _provider.GetAllUsers(0, 10, out int totalRecords);
            Console.WriteLine($"Total users found: {totalRecords}");

            foreach (var user in users) {
                Console.WriteLine($"User: {user.UserName}, Email: {user.Email}");
            }
        }

        // 11. Test get number of users online
        public void TestGetNumberOfUsersOnline()
        {
            Console.WriteLine("Running TestGetNumberOfUsersOnline...");

            var usersOnline = _provider.GetNumberOfUsersOnline();
            Console.WriteLine($"Number of users online: {usersOnline}");
        }
    }

}
