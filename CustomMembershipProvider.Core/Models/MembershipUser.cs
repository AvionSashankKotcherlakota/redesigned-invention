using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Models
{
    public class MembershipUser
    {
        public string ProviderName { get; private set; }
        public string UserName { get; private set; }
        public object ProviderUserKey { get; private set; }
        public string Email { get; set; }
        public string PasswordQuestion { get; set; }
        public string Comment { get; set; }
        public bool IsApproved { get; set; }
        public bool IsLockedOut { get; private set; }
        public DateTime CreationDate { get; private set; }
        public DateTime LastLoginDate { get; set; }
        public DateTime LastActivityDate { get; set; }
        public DateTime LastPasswordChangedDate { get; private set; }
        public DateTime LastLockoutDate { get; private set; }

        public MembershipUser(string providerName, string username, object providerUserKey, string email,
                              string passwordQuestion, string comment, bool isApproved, bool isLockedOut,
                              DateTime creationDate, DateTime lastLoginDate, DateTime lastActivityDate,
                              DateTime lastPasswordChangedDate, DateTime lastLockoutDate)
        {
            ProviderName = providerName;
            UserName = username;
            ProviderUserKey = providerUserKey;
            Email = email;
            PasswordQuestion = passwordQuestion;
            Comment = comment;
            IsApproved = isApproved;
            IsLockedOut = isLockedOut;
            CreationDate = creationDate;
            LastLoginDate = lastLoginDate;
            LastActivityDate = lastActivityDate;
            LastPasswordChangedDate = lastPasswordChangedDate;
            LastLockoutDate = lastLockoutDate;
        }
    }
}
