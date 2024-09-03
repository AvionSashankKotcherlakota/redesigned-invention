using System;
using System.Collections.Specialized;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Configuration.Provider;
using Microsoft.Extensions.Configuration;
using CustomMembershipProvider.Core.Models;
using CustomMembershipProvider.Core.Utilities;
using CustomMembershipProvider.Core.Interfaces;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;

namespace CustomMembershipProvider.Core.Providers
{
    public class CustomSqlMembershipProvider : ICustomSqlMembershipProvider
    {
        private readonly IDataProtector _protector;

        private string _applicationName;
        private string _name;
        private string _description;
        private bool _enablePasswordReset;
        private bool _enablePasswordRetrieval;
        private bool _requiresQuestionAndAnswer;
        private bool _requiresUniqueEmail;
        private int _maxInvalidPasswordAttempts;
        private int _passwordAttemptWindow;
        private int _minRequiredPasswordLength;
        private int _minRequiredNonAlphanumericCharacters;
        private string _passwordStrengthRegularExpression;
        private MembershipPasswordFormat _passwordFormat;
        private string _sqlConnectionString;
        private int _schemaVersionCheck;
        private int _commandTimeout;
        private int _userIsOnlineTimeWindow;

        private string _hashAlgorithmName;
        private MembershipPasswordCompatibilityMode _legacyPasswordCompatibilityMode = MembershipPasswordCompatibilityMode.Framework20; // Default to Framework20 for compatibility


        private MembershipValidatePasswordEventHandler _EventHandler;

        public string ApplicationName
        {
            get => _applicationName;
            set => _applicationName = value;
        }

        public bool EnablePasswordReset => _enablePasswordReset;
        public bool EnablePasswordRetrieval => _enablePasswordRetrieval;
        public int MaxInvalidPasswordAttempts => _maxInvalidPasswordAttempts;
        public int MinRequiredNonAlphanumericCharacters => _minRequiredNonAlphanumericCharacters;
        public int MinRequiredPasswordLength => _minRequiredPasswordLength;
        public int PasswordAttemptWindow => _passwordAttemptWindow;
        public MembershipPasswordFormat PasswordFormat => _passwordFormat;
        public string PasswordStrengthRegularExpression => _passwordStrengthRegularExpression;
        public bool RequiresQuestionAndAnswer => _requiresQuestionAndAnswer;
        public bool RequiresUniqueEmail => _requiresUniqueEmail;

        public int UserIsOnlineTimeWindow => _userIsOnlineTimeWindow;

        public string Name => _name;

        /// <summary>
        /// Gets a brief, friendly description suitable for display in administrative tools or other user interfaces (UIs).
        /// </summary>
        /// <returns>A brief, friendly description suitable for display in administrative tools or other UIs.</returns>
        public string Description
        {
            get => !string.IsNullOrEmpty(_description) ? _description : Name;
        }


        // Constructor for dependency injection
        public CustomSqlMembershipProvider(IConfiguration configuration, string connectionStringName, IDataProtectionProvider dataProtectionProvider)
        {
            _sqlConnectionString = SecUtility.GetConnectionString(configuration, new NameValueCollection { ["connectionStringName"] = connectionStringName });
            _applicationName = configuration["applicationName"] ?? "MyApp";
            _requiresQuestionAndAnswer = SecUtility.GetBooleanValue(configuration, "requiresQuestionAndAnswer", true);
            _requiresUniqueEmail = SecUtility.GetBooleanValue(configuration, "requiresUniqueEmail", true);
            _enablePasswordRetrieval = SecUtility.GetBooleanValue(configuration, "enablePasswordRetrieval", false);
            _enablePasswordReset = SecUtility.GetBooleanValue(configuration, "enablePasswordReset", true);
            _maxInvalidPasswordAttempts = SecUtility.GetIntValue(configuration, "maxInvalidPasswordAttempts", 5, true, 0);
            _passwordAttemptWindow = SecUtility.GetIntValue(configuration, "passwordAttemptWindow", 10, true, 0);
            _minRequiredPasswordLength = SecUtility.GetIntValue(configuration, "minRequiredPasswordLength", 7, true, 128);
            _minRequiredNonAlphanumericCharacters = SecUtility.GetIntValue(configuration, "minRequiredNonAlphanumericCharacters", 1, true, 128);
            _passwordStrengthRegularExpression = configuration["passwordStrengthRegularExpression"];
            _passwordFormat = MembershipPasswordFormat.Hashed;  // Default password format
            _schemaVersionCheck = 0;
            _commandTimeout = SecUtility.GetIntValue(configuration, "commandTimeout", 30, true, 0);

            _userIsOnlineTimeWindow = configuration.GetValue<int>("MembershipSettings:UserIsOnlineTimeWindow", 15);
            // Initialize the data protector
            _protector = dataProtectionProvider.CreateProtector("CustomSqlMembershipProvider");
        }

        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            // Validate parameters using SecUtility
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));
            SecUtility.CheckParameter(ref oldPassword, true, true, false, 128, nameof(oldPassword));
            SecUtility.CheckParameter(ref newPassword, true, true, false, 128, nameof(newPassword));

            string salt = (string)null;
            int passwordFormat;
            if (!this.CheckPassword(username, oldPassword, false, false, out salt, out passwordFormat))
                return false;

            // Check password complexity and length constraints
            if (newPassword.Length < _minRequiredPasswordLength) {
                throw new ArgumentException($"The new password must be at least {_minRequiredPasswordLength} characters long.", nameof(newPassword));
            }

            int nonAlphanumericCount = 0;
            foreach (char c in newPassword) {
                if (!char.IsLetterOrDigit(c)) {
                    nonAlphanumericCount++;
                }
            }

            if (nonAlphanumericCount < _minRequiredNonAlphanumericCharacters) {
                throw new ArgumentException($"The new password must contain at least {_minRequiredNonAlphanumericCharacters} non-alphanumeric characters.", nameof(newPassword));
            }

            if (!string.IsNullOrEmpty(_passwordStrengthRegularExpression) && !System.Text.RegularExpressions.Regex.IsMatch(newPassword, _passwordStrengthRegularExpression)) {
                throw new ArgumentException("The new password does not meet the password strength requirements.", nameof(newPassword));
            }

            // Validate the new password through the OnValidatingPassword event
            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, newPassword, false);
            this.OnValidatingPassword(e);
            if (e.Cancel) {
                if (e.FailureInformation != null) {
                    throw e.FailureInformation;
                }
                throw new ArgumentException("Password validation failed.", nameof(newPassword));
            }

            // Encode the new password
            string encodedPassword = EncodePassword(newPassword, passwordFormat, salt);

            if (encodedPassword.Length > 128)  // Assuming 128 is the maximum allowed length for encoded passwords
            {
                throw new ArgumentException("The new password is too long.", nameof(newPassword));
            }

            // Update the password in the database
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();
                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_SetPassword", connection)) {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@ApplicationName", ApplicationName);
                        cmd.Parameters.AddWithValue("@UserName", username);
                        cmd.Parameters.AddWithValue("@NewPassword", encodedPassword);
                        cmd.Parameters.AddWithValue("@PasswordSalt", salt);
                        cmd.Parameters.AddWithValue("@PasswordFormat", passwordFormat);
                        cmd.Parameters.AddWithValue("@CurrentTimeUtc", DateTime.UtcNow);

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        return (int)returnValue.Value == 0;  // Return true if password update was successful
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error changing password.", ex);
            }
        }

        public bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            // Validate parameters using SecUtility
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));
            SecUtility.CheckParameter(ref password, true, true, false, 128, nameof(password));

            // Check the provided password and retrieve salt and format
            string salt;
            int passwordFormat;
            if (!CheckPassword(username, password, false, false, out salt, out passwordFormat)) {
                return false;  // Provided password is incorrect
            }

            // Validate the new password question
            SecUtility.CheckParameter(ref newPasswordQuestion, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 256, nameof(newPasswordQuestion));

            // Trim the new password answer if not null
            if (newPasswordAnswer != null) {
                newPasswordAnswer = newPasswordAnswer.Trim();
            }

            // Validate the new password answer
            SecUtility.CheckParameter(ref newPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, nameof(newPasswordAnswer));

            // Encode the new password answer if it's not null or empty
            string encodedAnswer = string.IsNullOrEmpty(newPasswordAnswer)
                ? newPasswordAnswer
                : EncodePassword(newPasswordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, salt);

            // Validate the encoded answer
            SecUtility.CheckParameter(ref encodedAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, nameof(newPasswordAnswer));

            // Update the password question and answer in the database
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();
                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_ChangePasswordQuestionAndAnswer", connection)) {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@ApplicationName", ApplicationName);
                        cmd.Parameters.AddWithValue("@UserName", username);
                        cmd.Parameters.AddWithValue("@NewPasswordQuestion", newPasswordQuestion);
                        cmd.Parameters.AddWithValue("@NewPasswordAnswer", encodedAnswer);

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        return (int)returnValue.Value == 0;  // Return true if the update was successful
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error changing password question and answer.", ex);
            }
        }

        public MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            // Validate password parameter
            if (!SecUtility.ValidateParameter(ref password, true, true, false, 128)) {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            // Generate salt and encode password
            string salt = GenerateSalt();
            string encodedPassword = EncodePassword(password, (int)_passwordFormat, salt);
            if (encodedPassword.Length > 128) {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            // Trim and validate password answer
            if (passwordAnswer != null) {
                passwordAnswer = passwordAnswer.Trim();
            }

            string encodedPasswordAnswer = !string.IsNullOrEmpty(passwordAnswer)
                ? EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), (int)_passwordFormat, salt)
                : passwordAnswer;

            if (!SecUtility.ValidateParameter(ref encodedPasswordAnswer, RequiresQuestionAndAnswer, true, false, 128)) {
                status = MembershipCreateStatus.InvalidAnswer;
                return null;
            }

            // Validate other parameters
            if (!SecUtility.ValidateParameter(ref username, true, true, true, 256)) {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref email, RequiresUniqueEmail, RequiresUniqueEmail, false, 256)) {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref passwordQuestion, RequiresQuestionAndAnswer, true, false, 256)) {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            // Handle provider user key validation
            switch (providerUserKey) {
                case null:
                case Guid _:
                    // Perform additional password validations
                    if (password.Length < MinRequiredPasswordLength) {
                        status = MembershipCreateStatus.InvalidPassword;
                        return null;
                    }

                    int nonAlphanumericCount = password.Count(c => !char.IsLetterOrDigit(c));
                    if (nonAlphanumericCount < MinRequiredNonAlphanumericCharacters) {
                        status = MembershipCreateStatus.InvalidPassword;
                        return null;
                    }

                    if (!string.IsNullOrEmpty(PasswordStrengthRegularExpression) &&
                        !Regex.IsMatch(password, PasswordStrengthRegularExpression, RegexOptions.None)) {
                        status = MembershipCreateStatus.InvalidPassword;
                        return null;
                    }

                    // Validate password event
                    ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, password, true);
                    OnValidatingPassword(e);
                    if (e.Cancel) {
                        status = MembershipCreateStatus.InvalidPassword;
                        return null;
                    }

                    try {
                        // Database interaction
                        using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                            connection.Open();
                            CheckSchemaVersion(connection);

                            DateTime utcNow = DateTime.UtcNow;
                            using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_CreateUser", connection)) {
                                cmd.CommandTimeout = CommandTimeout;
                                cmd.CommandType = CommandType.StoredProcedure;

                                // Add parameters to the stored procedure
                                cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                                cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                                cmd.Parameters.Add(CreateInputParam("@Password", SqlDbType.NVarChar, encodedPassword));
                                cmd.Parameters.Add(CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, salt));
                                cmd.Parameters.Add(CreateInputParam("@Email", SqlDbType.NVarChar, email));
                                cmd.Parameters.Add(CreateInputParam("@PasswordQuestion", SqlDbType.NVarChar, passwordQuestion));
                                cmd.Parameters.Add(CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
                                cmd.Parameters.Add(CreateInputParam("@IsApproved", SqlDbType.Bit, isApproved));
                                cmd.Parameters.Add(CreateInputParam("@UniqueEmail", SqlDbType.Int, RequiresUniqueEmail ? 1 : 0));
                                cmd.Parameters.Add(CreateInputParam("@PasswordFormat", SqlDbType.Int, (int)_passwordFormat));
                                cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, utcNow));

                                // Handle user key (if provided)
                                SqlParameter userIdParam = CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey);
                                userIdParam.Direction = ParameterDirection.InputOutput;
                                cmd.Parameters.Add(userIdParam);

                                // Return value
                                SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                                    Direction = ParameterDirection.ReturnValue
                                };
                                cmd.Parameters.Add(returnValue);

                                try {
                                    cmd.ExecuteNonQuery();
                                }
                                catch (SqlException ex) when (ex.Number == 2627 || ex.Number == 2601 || ex.Number == 2512) {
                                    status = MembershipCreateStatus.DuplicateUserName;
                                    return null;
                                }

                                // Handle return value from stored procedure
                                int result = (int)(returnValue.Value ?? -1);
                                if (result < 0 || result > 11) {
                                    result = 11; // Unknown failure
                                }
                                status = (MembershipCreateStatus)result;

                                if (status != MembershipCreateStatus.Success) {
                                    return null;
                                }

                                // Retrieve the generated user ID
                                providerUserKey = (Guid)userIdParam.Value;

                                // Return the newly created MembershipUser
                                DateTime localDateTime = utcNow.ToLocalTime();
                                return new MembershipUser(
                                    Name, username, providerUserKey, email, passwordQuestion, null,
                                    isApproved, false, localDateTime, localDateTime,
                                    localDateTime, localDateTime, new DateTime(1754, 1, 1));
                            }
                        }
                    }
                    catch {
                        throw;
                    }

                default:
                    status = MembershipCreateStatus.InvalidProviderUserKey;
                    return null;
            }
        }

        public bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            // Validate the username parameter
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Users_DeleteUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));

                        // Determine the tables to delete from based on the deleteAllRelatedData flag
                        int tablesToDeleteFrom = deleteAllRelatedData ? 15 : 1;
                        cmd.Parameters.Add(CreateInputParam("@TablesToDeleteFrom", SqlDbType.Int, tablesToDeleteFrom));

                        SqlParameter outputParam = new SqlParameter("@NumTablesDeletedFrom", SqlDbType.Int) {
                            Direction = ParameterDirection.Output
                        };
                        cmd.Parameters.Add(outputParam);

                        // Execute the command
                        cmd.ExecuteNonQuery();

                        // Return true if the user was deleted from at least one table
                        return (outputParam.Value != null ? (int)outputParam.Value : -1) > 0;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error deleting user.", ex);
            }
        }

        public byte[] EncryptPassword(byte[] password)
        {
            return this.EncryptPassword(password, MembershipPasswordCompatibilityMode.Framework20);
        }

        public byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode)
        {
            return EncryptOrDecryptData(true, password, legacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework20);
        }

        public MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            // Validate the emailToMatch parameter
            SecUtility.CheckParameter(ref emailToMatch, false, false, false, 256, nameof(emailToMatch));

            // Validate the pageIndex and pageSize parameters
            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be less than 0.", nameof(pageIndex));
            if (pageSize < 1)
                throw new ArgumentException("PageSize cannot be less than 1.", nameof(pageSize));
            if ((long)pageIndex * pageSize + pageSize - 1L > int.MaxValue)
                throw new ArgumentException("The combination of pageIndex and pageSize is invalid.", "pageIndex and pageSize");

            totalRecords = 0;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByEmail", connection)) {
                        MembershipUserCollection usersByEmail = new MembershipUserCollection();
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@EmailToMatch", SqlDbType.NVarChar, emailToMatch));
                        cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = GetNullableString(reader, 0);
                                string email = GetNullableString(reader, 1);
                                string passwordQuestion = GetNullableString(reader, 2);
                                string comment = GetNullableString(reader, 3);
                                bool isApproved = reader.GetBoolean(4);
                                DateTime creationDate = reader.GetDateTime(5).ToLocalTime();
                                DateTime lastLoginDate = reader.GetDateTime(6).ToLocalTime();
                                DateTime lastActivityDate = reader.GetDateTime(7).ToLocalTime();
                                DateTime lastPasswordChangedDate = reader.GetDateTime(8).ToLocalTime();
                                Guid providerUserKey = reader.GetGuid(9);
                                bool isLockedOut = reader.GetBoolean(10);
                                DateTime lastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                                usersByEmail.Add(new MembershipUser(
                                    Name,
                                    username,
                                    providerUserKey,
                                    email,
                                    passwordQuestion,
                                    comment,
                                    isApproved,
                                    isLockedOut,
                                    creationDate,
                                    lastLoginDate,
                                    lastActivityDate,
                                    lastPasswordChangedDate,
                                    lastLockoutDate
                                ));
                            }
                        }

                        if (returnValue.Value != null && returnValue.Value is int) {
                            totalRecords = (int)returnValue.Value;
                        }

                        return usersByEmail;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error finding users by email.", ex);
            }
        }

        public MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            // Validate the usernameToMatch parameter
            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 256, nameof(usernameToMatch));

            // Validate the pageIndex and pageSize parameters
            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be less than 0.", nameof(pageIndex));
            if (pageSize < 1)
                throw new ArgumentException("PageSize cannot be less than 1.", nameof(pageSize));
            if ((long)pageIndex * pageSize + pageSize - 1L > int.MaxValue)
                throw new ArgumentException("The combination of pageIndex and pageSize is invalid.", "pageIndex and pageSize");

            totalRecords = 0;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByName", connection)) {
                        MembershipUserCollection usersByName = new MembershipUserCollection();
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserNameToMatch", SqlDbType.NVarChar, usernameToMatch));
                        cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = GetNullableString(reader, 0);
                                string email = GetNullableString(reader, 1);
                                string passwordQuestion = GetNullableString(reader, 2);
                                string comment = GetNullableString(reader, 3);
                                bool isApproved = reader.GetBoolean(4);
                                DateTime creationDate = reader.GetDateTime(5).ToLocalTime();
                                DateTime lastLoginDate = reader.GetDateTime(6).ToLocalTime();
                                DateTime lastActivityDate = reader.GetDateTime(7).ToLocalTime();
                                DateTime lastPasswordChangedDate = reader.GetDateTime(8).ToLocalTime();
                                Guid providerUserKey = reader.GetGuid(9);
                                bool isLockedOut = reader.GetBoolean(10);
                                DateTime lastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                                usersByName.Add(new MembershipUser(
                                    Name,
                                    username,
                                    providerUserKey,
                                    email,
                                    passwordQuestion,
                                    comment,
                                    isApproved,
                                    isLockedOut,
                                    creationDate,
                                    lastLoginDate,
                                    lastActivityDate,
                                    lastPasswordChangedDate,
                                    lastLockoutDate
                                ));
                            }
                        }

                        if (returnValue.Value != null && returnValue.Value is int) {
                            totalRecords = (int)returnValue.Value;
                        }

                        return usersByName;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error finding users by name.", ex);
            }
        }

        public string GeneratePassword()
        {
            int length = MinRequiredPasswordLength < 14 ? 14 : MinRequiredPasswordLength;
            int numberOfNonAlphanumericCharacters = MinRequiredNonAlphanumericCharacters;

            return MembershipHelper.GeneratePassword(length, numberOfNonAlphanumericCharacters);
        }

        public MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be less than 0.", nameof(pageIndex));
            if (pageSize < 1)
                throw new ArgumentException("PageSize cannot be less than 1.", nameof(pageSize));
            if ((long)pageIndex * pageSize + pageSize - 1L > int.MaxValue)
                throw new ArgumentException("The combination of pageIndex and pageSize is invalid.", "pageIndex and pageSize");

            MembershipUserCollection allUsers = new MembershipUserCollection();
            totalRecords = 0;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetAllUsers", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = GetNullableString(reader, 0);
                                string email = GetNullableString(reader, 1);
                                string passwordQuestion = GetNullableString(reader, 2);
                                string comment = GetNullableString(reader, 3);
                                bool isApproved = reader.GetBoolean(4);
                                DateTime creationDate = reader.GetDateTime(5).ToLocalTime();
                                DateTime lastLoginDate = reader.GetDateTime(6).ToLocalTime();
                                DateTime lastActivityDate = reader.GetDateTime(7).ToLocalTime();
                                DateTime lastPasswordChangedDate = reader.GetDateTime(8).ToLocalTime();
                                Guid providerUserKey = reader.GetGuid(9);
                                bool isLockedOut = reader.GetBoolean(10);
                                DateTime lastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                                allUsers.Add(new MembershipUser(
                                    Name,
                                    username,
                                    providerUserKey,
                                    email,
                                    passwordQuestion,
                                    comment,
                                    isApproved,
                                    isLockedOut,
                                    creationDate,
                                    lastLoginDate,
                                    lastActivityDate,
                                    lastPasswordChangedDate,
                                    lastLockoutDate
                                ));
                            }
                        }

                        if (returnValue.Value != null && returnValue.Value is int) {
                            totalRecords = (int)returnValue.Value;
                        }
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving all users.", ex);
            }

            return allUsers;
        }

        public int GetNumberOfUsersOnline()
        {
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetNumberOfUsersOnline", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@MinutesSinceLastInActive", SqlDbType.Int, UserIsOnlineTimeWindow));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        return returnValue.Value != null ? (int)returnValue.Value : -1;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving the number of users online.", ex);
            }
        }

        public string GetPassword(string username, string passwordAnswer)
        {
            if (!this.EnablePasswordRetrieval)
                throw new NotSupportedException("Password retrieval is not supported.");

            // Validate the username parameter
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));

            // Encode the provided password answer
            string encodedPasswordAnswer = this.GetEncodedPasswordAnswer(username, passwordAnswer);

            // Validate the encoded password answer parameter
            SecUtility.CheckParameter(ref encodedPasswordAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, 128, nameof(passwordAnswer));

            int passwordFormat = 0;
            int status = 0;

            // Retrieve the password from the database
            string passwordFromDb = this.GetPasswordFromDB(username, encodedPasswordAnswer, this.RequiresQuestionAndAnswer, out passwordFormat, out status);

            // If a password was retrieved, unencode it and return
            if (passwordFromDb != null)
                return this.UnEncodePassword(passwordFromDb, passwordFormat);

            // Handle errors based on the status code
            string exceptionText = GetExceptionText(status);

            if (IsStatusDueToBadPassword(status))
                throw new Exception(exceptionText);

            throw new ProviderException(exceptionText);
        }

        public MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (providerUserKey == null)
                throw new ArgumentNullException(nameof(providerUserKey));

            if (!(providerUserKey is Guid))
                throw new ArgumentException("Invalid provider user key.", nameof(providerUserKey));

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByUserId", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey));
                        cmd.Parameters.Add(CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader()) {
                            if (!reader.Read())
                                return null;

                            string email = GetNullableString(reader, 0);
                            string passwordQuestion = GetNullableString(reader, 1);
                            string comment = GetNullableString(reader, 2);
                            bool isApproved = reader.GetBoolean(3);
                            DateTime creationDate = reader.GetDateTime(4).ToLocalTime();
                            DateTime lastLoginDate = reader.GetDateTime(5).ToLocalTime();
                            DateTime lastActivityDate = reader.GetDateTime(6).ToLocalTime();
                            DateTime lastPasswordChangedDate = reader.GetDateTime(7).ToLocalTime();
                            string userName = GetNullableString(reader, 8);
                            bool isLockedOut = reader.GetBoolean(9);
                            DateTime lastLockoutDate = reader.GetDateTime(10).ToLocalTime();

                            return new MembershipUser(
                                this.Name,
                                userName,
                                providerUserKey,
                                email,
                                passwordQuestion,
                                comment,
                                isApproved,
                                isLockedOut,
                                creationDate,
                                lastLoginDate,
                                lastActivityDate,
                                lastPasswordChangedDate,
                                lastLockoutDate);
                        }
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving user by user ID.", ex);
            }
        }

        public MembershipUser GetUser(string username, bool userIsOnline)
        {
            SecUtility.CheckParameter(ref username, true, false, true, 256, nameof(username));

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByName", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader()) {
                            if (!reader.Read())
                                return null;

                            string email = GetNullableString(reader, 0);
                            string passwordQuestion = GetNullableString(reader, 1);
                            string comment = GetNullableString(reader, 2);
                            bool isApproved = reader.GetBoolean(3);
                            DateTime creationDate = reader.GetDateTime(4).ToLocalTime();
                            DateTime lastLoginDate = reader.GetDateTime(5).ToLocalTime();
                            DateTime lastActivityDate = reader.GetDateTime(6).ToLocalTime();
                            DateTime lastPasswordChangedDate = reader.GetDateTime(7).ToLocalTime();
                            Guid providerUserKey = reader.GetGuid(8);
                            bool isLockedOut = reader.GetBoolean(9);
                            DateTime lastLockoutDate = reader.GetDateTime(10).ToLocalTime();

                            return new MembershipUser(
                                this.Name,
                                username,
                                providerUserKey,
                                email,
                                passwordQuestion,
                                comment,
                                isApproved,
                                isLockedOut,
                                creationDate,
                                lastLoginDate,
                                lastActivityDate,
                                lastPasswordChangedDate,
                                lastLockoutDate);
                        }
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving user by username.", ex);
            }
        }

        public string GetUserNameByEmail(string email)
        {
            SecUtility.CheckParameter(ref email, false, false, false, 256, nameof(email));

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByEmail", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@Email", SqlDbType.NVarChar, email));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            string userNameByEmail = null;
                            if (reader.Read()) {
                                userNameByEmail = GetNullableString(reader, 0);
                                if (RequiresUniqueEmail && reader.Read()) {
                                    throw new ProviderException("More than one user with the same email.");
                                }
                            }
                            return userNameByEmail;
                        }
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving username by email.", ex);
            }
        }

        public void Initialize(string name, NameValueCollection config)
        {
            throw new NotImplementedException();
        }

        public string ResetPassword(string username, string passwordAnswer)
        {
            if (!EnablePasswordReset)
                throw new NotSupportedException("Password resets are not enabled.");

            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));

            int status;
            int passwordFormat;
            string passwordSalt;

            GetPasswordWithFormat(username, false, out status, out string _, out passwordFormat, out passwordSalt, out int _, out int _, out bool _, out DateTime _, out DateTime _);

            if (status != 0) {
                if (IsStatusDueToBadPassword(status))
                    throw new Exception(GetExceptionText(status));
                throw new ProviderException(GetExceptionText(status));
            }

            if (passwordAnswer != null)
                passwordAnswer = passwordAnswer.Trim();

            string encodedPasswordAnswer = string.IsNullOrEmpty(passwordAnswer)
                ? passwordAnswer
                : EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, passwordSalt);

            SecUtility.CheckParameter(ref encodedPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, nameof(passwordAnswer));

            string newPassword = GeneratePassword();
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(args);

            if (args.Cancel) {
                if (args.FailureInformation != null)
                    throw args.FailureInformation;
                throw new ProviderException("Password validation failed.");
            }

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_ResetPassword", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@NewPassword", SqlDbType.NVarChar, EncodePassword(newPassword, passwordFormat, passwordSalt)));
                        cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, MaxInvalidPasswordAttempts));
                        cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, PasswordAttemptWindow));
                        cmd.Parameters.Add(CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, passwordSalt));
                        cmd.Parameters.Add(CreateInputParam("@PasswordFormat", SqlDbType.Int, passwordFormat));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        if (RequiresQuestionAndAnswer) {
                            cmd.Parameters.Add(CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
                        }

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        int resetStatus = returnValue.Value != null ? (int)returnValue.Value : -1;
                        if (resetStatus == 0)
                            return newPassword;

                        string exceptionText = GetExceptionText(resetStatus);
                        if (IsStatusDueToBadPassword(resetStatus))
                            throw new Exception(exceptionText);
                        throw new ProviderException(exceptionText);
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error resetting password.", ex);
            }
        }

        public bool UnlockUser(string username)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UnlockUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        return (returnValue.Value != null ? (int)returnValue.Value : -1) == 0;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error unlocking user.", ex);
            }
        }

        public void UpdateUser(MembershipUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            string userName = user.UserName;
            SecUtility.CheckParameter(ref userName, true, true, true, 256, "UserName");

            string email = user.Email;
            SecUtility.CheckParameter(ref email, RequiresUniqueEmail, RequiresUniqueEmail, false, 256, "Email");

            user.Email = email;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, user.UserName));
                        cmd.Parameters.Add(CreateInputParam("@Email", SqlDbType.NVarChar, user.Email));
                        cmd.Parameters.Add(CreateInputParam("@Comment", SqlDbType.NText, user.Comment));
                        cmd.Parameters.Add(CreateInputParam("@IsApproved", SqlDbType.Bit, user.IsApproved ? 1 : 0));
                        cmd.Parameters.Add(CreateInputParam("@LastLoginDate", SqlDbType.DateTime, user.LastLoginDate.ToUniversalTime()));
                        cmd.Parameters.Add(CreateInputParam("@LastActivityDate", SqlDbType.DateTime, user.LastActivityDate.ToUniversalTime()));
                        cmd.Parameters.Add(CreateInputParam("@UniqueEmail", SqlDbType.Int, RequiresUniqueEmail ? 1 : 0));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        int status = returnValue.Value != null ? (int)returnValue.Value : -1;
                        if (status != 0)
                            throw new ProviderException(GetExceptionText(status));
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error updating user.", ex);
            }
        }

        public bool ValidateUser(string username, string password)
        {
            if (SecUtility.ValidateParameter(ref username, true, true, true, 256) &&
                SecUtility.ValidateParameter(ref password, true, true, false, 128) &&
                this.CheckPassword(username, password, true, true)) {
                return true;
            }

            return false;
        }


        #region Helper Methods

        private string GenerateSalt()
        {
            byte[] buffer = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) {
                rng.GetBytes(buffer);
            }
            return Convert.ToBase64String(buffer);
        }

        private string EncodePassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
            {
                return pass;
            }

            byte[] passwordBytes = Encoding.Unicode.GetBytes(pass);
            byte[] saltBytes = Convert.FromBase64String(salt);
            byte[] inArray;

            if (passwordFormat == 1) // MembershipPasswordFormat.Hashed
            {
                using (HashAlgorithm hashAlgorithm = GetHashAlgorithm()) {
                    if (hashAlgorithm is KeyedHashAlgorithm keyedHashAlgorithm) {
                        // Handle KeyedHashAlgorithm with salt as key
                        keyedHashAlgorithm.Key = GetKeyedHashKey(keyedHashAlgorithm, saltBytes);
                        inArray = keyedHashAlgorithm.ComputeHash(passwordBytes);
                    } else {
                        // Combine salt and password bytes and hash them
                        byte[] saltedPassword = CombineBytes(saltBytes, passwordBytes);
                        inArray = hashAlgorithm.ComputeHash(saltedPassword);
                    }
                }
            } else // MembershipPasswordFormat.Encrypted
              {
                byte[] saltedPassword = CombineBytes(saltBytes, passwordBytes);
                inArray = EncryptPassword(saltedPassword);
            }

            return Convert.ToBase64String(inArray);
        }

        private byte[] GetKeyedHashKey(KeyedHashAlgorithm algorithm, byte[] salt)
        {
            if (algorithm.Key.Length == salt.Length) {
                return salt;
            } else if (algorithm.Key.Length < salt.Length) {
                byte[] key = new byte[algorithm.Key.Length];
                Buffer.BlockCopy(salt, 0, key, 0, key.Length);
                return key;
            } else {
                byte[] key = new byte[algorithm.Key.Length];
                int count;
                for (int dstOffset = 0; dstOffset < key.Length; dstOffset += count) {
                    count = Math.Min(salt.Length, key.Length - dstOffset);
                    Buffer.BlockCopy(salt, 0, key, dstOffset, count);
                }
                return key;
            }
        }

        private byte[] CombineBytes(byte[] first, byte[] second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }

        private void GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, out int status, out string password, out int passwordFormat, out string passwordSalt,
                                        out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate)
        {
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetPasswordWithFormat", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
                            status = -1;

                            if (reader.Read()) {
                                password = reader.GetString(0);
                                passwordFormat = reader.GetInt32(1);
                                passwordSalt = reader.GetString(2);
                                failedPasswordAttemptCount = reader.GetInt32(3);
                                failedPasswordAnswerAttemptCount = reader.GetInt32(4);
                                isApproved = reader.GetBoolean(5);
                                lastLoginDate = reader.GetDateTime(6);
                                lastActivityDate = reader.GetDateTime(7);
                            } else {
                                password = null;
                                passwordFormat = 0;
                                passwordSalt = null;
                                failedPasswordAttemptCount = 0;
                                failedPasswordAnswerAttemptCount = 0;
                                isApproved = false;
                                lastLoginDate = DateTime.UtcNow;
                                lastActivityDate = DateTime.UtcNow;
                            }
                        }

                        status = returnValue.Value != null ? (int)returnValue.Value : -1;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving password with format.", ex);
            }
        }

        private string GetPasswordFromDB(string username, string passwordAnswer, bool requiresQuestionAndAnswer, out int passwordFormat, out int status)
        {
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetPassword", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, MaxInvalidPasswordAttempts));
                        cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, PasswordAttemptWindow));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        if (requiresQuestionAndAnswer)
                            cmd.Parameters.Add(CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, passwordAnswer));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
                            status = -1;
                            string passwordFromDb = null;

                            if (reader.Read()) {
                                passwordFromDb = reader.GetString(0);
                                passwordFormat = reader.GetInt32(1);
                            } else {
                                passwordFromDb = null;
                                passwordFormat = 0;
                            }

                            status = returnValue.Value != null ? (int)returnValue.Value : -1;
                            return passwordFromDb;
                        }
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving password from database.", ex);
            }
        }

        private SqlParameter CreateInputParam(string paramName, SqlDbType dbType, object objValue)
        {
            SqlParameter inputParam = new SqlParameter(paramName, dbType);
            if (objValue == null) {
                inputParam.IsNullable = true;
                inputParam.Value = DBNull.Value;
            } else {
                inputParam.Value = objValue;
            }
            return inputParam;
        }

        private bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, out string salt, out int passwordFormat)
        {
            // Retrieve the stored password information
            this.GetPasswordWithFormat(username, updateLastLoginActivityDate, out int status, out string storedPassword, out passwordFormat, out salt,
                out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate);

            // Check if the status is not successful or the user is not approved and failIfNotApproved is true
            if (status != 0 || (!isApproved && failIfNotApproved))
                return false;

            // Encode the provided password with the same format and salt used for the stored password
            string encodedPassword = this.EncodePassword(password, passwordFormat, salt);

            // Compare the encoded password with the stored password
            bool isPasswordCorrect = storedPassword.Equals(encodedPassword);

            // If the password is correct and there are no failed attempts, return true
            if (isPasswordCorrect && failedPasswordAttemptCount == 0 && failedPasswordAnswerAttemptCount == 0)
                return true;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUserInfo", connection)) {
                        DateTime utcNow = DateTime.UtcNow;
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@IsPasswordCorrect", SqlDbType.Bit, isPasswordCorrect));
                        cmd.Parameters.Add(CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
                        cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, MaxInvalidPasswordAttempts));
                        cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, PasswordAttemptWindow));
                        cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, utcNow));
                        cmd.Parameters.Add(CreateInputParam("@LastLoginDate", SqlDbType.DateTime, isPasswordCorrect ? utcNow : lastLoginDate));
                        cmd.Parameters.Add(CreateInputParam("@LastActivityDate", SqlDbType.DateTime, isPasswordCorrect ? utcNow : lastActivityDate));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        int result = returnValue.Value != null ? (int)returnValue.Value : -1;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error updating user information.", ex);
            }

            return isPasswordCorrect;
        }

        private bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved)
        {
            return CheckPassword(username, password, updateLastLoginActivityDate, failIfNotApproved, out string _, out int _);
        }

        private void CheckSchemaVersion(SqlConnection connection)
        {
            string[] features = new string[2]
            {
        "Common",
        "Membership"
            };
            string version = "1";
            SecUtility.CheckSchemaVersion(this, connection, features, version, ref this._schemaVersionCheck);
        }

        private string GetNullableString(SqlDataReader reader, int col)
        {
            return !reader.IsDBNull(col) ? reader.GetString(col) : null;
        }

        private string GetEncodedPasswordAnswer(string username, string passwordAnswer)
        {
            if (passwordAnswer != null)
                passwordAnswer = passwordAnswer.Trim();

            if (string.IsNullOrEmpty(passwordAnswer))
                return passwordAnswer;

            int status;
            int passwordFormat;
            string passwordSalt;

            // Get the password information including salt, format, etc.
            this.GetPasswordWithFormat(username, false, out status, out string _, out passwordFormat, out passwordSalt, out int _, out int _, out bool _, out DateTime _, out DateTime _);

            // If the status indicates success, encode the password answer using the format and salt
            if (status == 0)
                return this.EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, passwordSalt);

            // If status is not successful, throw an exception with the appropriate message
            throw new ProviderException(GetExceptionText(status));
        }

        internal static string GetExceptionText(int status)
        {
            string message;
            switch (status) {
                case 0:
                    return string.Empty;
                case 1:
                    message = "User not found.";
                    break;
                case 2:
                    message = "Wrong password.";
                    break;
                case 3:
                    message = "Wrong answer.";
                    break;
                case 4:
                    message = "Invalid password.";
                    break;
                case 5:
                    message = "Invalid question.";
                    break;
                case 6:
                    message = "Invalid answer.";
                    break;
                case 7:
                    message = "Invalid email.";
                    break;
                case 99:
                    message = "Account is locked out.";
                    break;
                default:
                    message = "An unknown error occurred.";
                    break;
            }
            return message;
        }

        private string UnEncodePassword(string pass, int passwordFormat)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
                return pass;

            if (passwordFormat == 1) // MembershipPasswordFormat.Hashed
                throw new ProviderException("Cannot decode a hashed password.");

            byte[] decodedBytes = this.DecryptPassword(Convert.FromBase64String(pass));
            return decodedBytes != null ? Encoding.Unicode.GetString(decodedBytes, 16, decodedBytes.Length - 16) : null;
        }

        private byte[] DecryptPassword(byte[] encodedPassword)
        {
            try {
                return EncryptOrDecryptData(false, encodedPassword, false);
            }
            catch {
                throw new ProviderException("Error decrypting password.");
            }
        }

        public byte[] EncryptOrDecryptData(bool encrypt, byte[] buffer, bool useLegacyMode)
        {
            if (encrypt) {
                return _protector.Protect(buffer);
            } else {
                return _protector.Unprotect(buffer);
            }
        }

        internal static bool IsStatusDueToBadPassword(int status)
        {
            return (status >= 2 && status <= 6) || status == 99;
        }

        private DateTime RoundToSeconds(DateTime utcDateTime)
        {
            return new DateTime(utcDateTime.Year, utcDateTime.Month, utcDateTime.Day, utcDateTime.Hour, utcDateTime.Minute, utcDateTime.Second, DateTimeKind.Utc);
        }

        private HashAlgorithm GetHashAlgorithm()
        {
            if (!string.IsNullOrEmpty(_hashAlgorithmName)) {
                return HashAlgorithm.Create(_hashAlgorithmName);
            }

            // Default hash algorithm
            string hashName = "SHA1"; // Use SHA1 by default

            if (_legacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework20) {
                hashName = "SHA1"; // SHA1 for Framework 2.0 compatibility
            }

            // Attempt to create the hash algorithm
            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashName);

            if (hashAlgorithm == null) {
                throw new InvalidOperationException($"The hash algorithm '{hashName}' could not be created.");
            }

            // Store the hash algorithm name for future use
            _hashAlgorithmName = hashName;

            return hashAlgorithm;
        }

        private int CommandTimeout => this._commandTimeout;

        #endregion

        protected virtual void OnValidatingPassword(ValidatePasswordEventArgs e)
        {
            if (this._EventHandler == null)
                return;
            this._EventHandler((object)this, e);
        }
    }
}