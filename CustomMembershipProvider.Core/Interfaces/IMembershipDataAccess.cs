using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Interfaces
{
    public interface IMembershipDataAccess
    {
        bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, out string salt, out int passwordFormat, ref int schemaVersionCheck);
        bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, ref int schemaVersionCheck);
        void CheckSchemaVersion(SqlConnection connection, ref int schemaVersionCheck);
        string GetEncodedPasswordAnswer(string username, string passwordAnswer, string applicationName, ref int schemaVersionCheck);
        string GetPasswordFromDB(string username, string passwordAnswer, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, bool requiresQuestionAndAnswer, out int passwordFormat, out int status, ref int schemaVersionCheck);
        void GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, string applicationName, out int status, out string password, out int passwordFormat, out string passwordSalt, out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate, ref int schemaVersionCheck);
    }
}
