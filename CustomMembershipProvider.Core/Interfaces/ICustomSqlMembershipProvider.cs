using CustomMembershipProvider.Core.Models;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Interfaces
{
    public interface ICustomSqlMembershipProvider
    {
        string ApplicationName { get; set; }
        bool EnablePasswordReset { get; }
        bool EnablePasswordRetrieval { get; }
        int MaxInvalidPasswordAttempts { get; }
        int MinRequiredNonAlphanumericCharacters { get; }
        int MinRequiredPasswordLength { get; }
        int PasswordAttemptWindow { get; }
        MembershipPasswordFormat PasswordFormat { get; }
        string PasswordStrengthRegularExpression { get; }
        bool RequiresQuestionAndAnswer { get; }
        bool RequiresUniqueEmail { get; }

        bool ChangePassword(string username, string oldPassword, string newPassword);
        bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer);
        MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status);
        bool DeleteUser(string username, bool deleteAllRelatedData);
        MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords);
        MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords);
        string GeneratePassword();
        MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords);
        int GetNumberOfUsersOnline();
        string GetPassword(string username, string passwordAnswer);
        MembershipUser GetUser(object providerUserKey, bool userIsOnline);
        MembershipUser GetUser(string username, bool userIsOnline);
        string GetUserNameByEmail(string email);
        void Initialize(string name, NameValueCollection config);
        string ResetPassword(string username, string passwordAnswer);
        bool UnlockUser(string username);
        void UpdateUser(MembershipUser user);
        bool ValidateUser(string username, string password);
    }

}
