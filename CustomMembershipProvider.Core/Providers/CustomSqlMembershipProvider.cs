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
        private readonly IMembershipDataAccess _membershipDataAccess;
        private readonly IPasswordUtility _passwordUtility;

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
        public int CommandTimeout => this._commandTimeout;
        public string Name => _name;

        /// <summary>
        /// Gets a brief, friendly description suitable for display in administrative tools or other user interfaces (UIs).
        /// </summary>
        /// <returns>A brief, friendly description suitable for display in administrative tools or other UIs.</returns>
        public string Description
        {
            get => !string.IsNullOrEmpty(_description) ? _description : Name;
        }

        public CustomSqlMembershipProvider(IConfiguration configuration, IDataProtectionProvider dataProtectionProvider)
        {
            _sqlConnectionString = configuration.GetConnectionString("DefaultConnection");

            // Access all membership settings from "MembershipSettings"
            var membershipSettings = configuration.GetSection("MembershipSettings");

            _applicationName = membershipSettings.GetValue<string>("ApplicationName") ?? SecUtility.GetDefaultAppName();

            // Check if application name is too long
            if (_applicationName.Length > 256) {
                throw new ProviderException("Application name too long. Maximum length is 256 characters.");
            }

            // Load values directly from the "MembershipSettings" section
            _requiresQuestionAndAnswer = membershipSettings.GetValue<bool>("RequiresQuestionAndAnswer", true);
            _requiresUniqueEmail = membershipSettings.GetValue<bool>("RequiresUniqueEmail", true);
            _enablePasswordRetrieval = membershipSettings.GetValue<bool>("EnablePasswordRetrieval", false);
            _enablePasswordReset = membershipSettings.GetValue<bool>("EnablePasswordReset", true);
            _maxInvalidPasswordAttempts = membershipSettings.GetValue<int>("MaxInvalidPasswordAttempts", 5);
            _passwordAttemptWindow = membershipSettings.GetValue<int>("PasswordAttemptWindow", 10);
            _minRequiredPasswordLength = membershipSettings.GetValue<int>("MinRequiredPasswordLength", 7);
            _minRequiredNonAlphanumericCharacters = membershipSettings.GetValue<int>("MinRequiredNonAlphanumericCharacters", 1);
            _passwordStrengthRegularExpression = membershipSettings.GetValue<string>("PasswordStrengthRegularExpression", string.Empty);

            if (!string.IsNullOrEmpty(_passwordStrengthRegularExpression)) {
                _passwordStrengthRegularExpression = _passwordStrengthRegularExpression.Trim();
                try {
                    Regex regex = new Regex(_passwordStrengthRegularExpression);
                }
                catch (ArgumentException ex) {
                    throw new ProviderException("Invalid password strength regular expression: " + ex.Message);
                }
            }

            string passwordFormatConfig = membershipSettings.GetValue<string>("PasswordFormat") ?? "Hashed";
            switch (passwordFormatConfig) {
                case "Clear":
                    _passwordFormat = MembershipPasswordFormat.Clear;
                    break;
                case "Encrypted":
                    _passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                default:
                    throw new ProviderException("Invalid password format: " + passwordFormatConfig);
            }

            if (_passwordFormat == MembershipPasswordFormat.Hashed && _enablePasswordRetrieval) {
                throw new ProviderException("Cannot retrieve hashed passwords.");
            }

            _schemaVersionCheck = 0; // Initialize as default (0)
            _commandTimeout = membershipSettings.GetValue<int>("CommandTimeout", 30); // Command timeout in seconds
            _userIsOnlineTimeWindow = membershipSettings.GetValue<int>("UserIsOnlineTimeWindow", 15); // Default online window
        }

        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            // Validate parameters using SecUtility
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));
            SecUtility.CheckParameter(ref oldPassword, true, true, false, 128, nameof(oldPassword));
            SecUtility.CheckParameter(ref newPassword, true, true, false, 128, nameof(newPassword));

            string salt = (string)null;
            int passwordFormat;
            if (!_membershipDataAccess.CheckPassword(username, oldPassword, false, false, ApplicationName, MaxInvalidPasswordAttempts, PasswordAttemptWindow, out salt, out passwordFormat, ref _schemaVersionCheck))
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
            string encodedPassword = _passwordUtility.EncodePassword(newPassword, passwordFormat, salt);

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
            if (!_membershipDataAccess.CheckPassword(username, password, false, false, ApplicationName, MaxInvalidPasswordAttempts, PasswordAttemptWindow, out salt, out passwordFormat, ref _schemaVersionCheck)) {
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
                : _passwordUtility.EncodePassword(newPasswordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, salt);

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
            string salt = _passwordUtility.GenerateSalt();
            string encodedPassword = _passwordUtility.EncodePassword(password, (int)_passwordFormat, salt);
            if (encodedPassword.Length > 128) {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            // Trim and validate password answer
            if (passwordAnswer != null) {
                passwordAnswer = passwordAnswer.Trim();
            }

            string encodedPasswordAnswer = !string.IsNullOrEmpty(passwordAnswer)
                ? _passwordUtility.EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), (int)_passwordFormat, salt)
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
                            _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                            DateTime utcNow = DateTime.UtcNow;
                            using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_CreateUser", connection)) {
                                cmd.CommandTimeout = CommandTimeout;
                                cmd.CommandType = CommandType.StoredProcedure;

                                // Add parameters to the stored procedure
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@Password", SqlDbType.NVarChar, encodedPassword));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, salt));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@Email", SqlDbType.NVarChar, email));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordQuestion", SqlDbType.NVarChar, passwordQuestion));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@IsApproved", SqlDbType.Bit, isApproved));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UniqueEmail", SqlDbType.Int, RequiresUniqueEmail ? 1 : 0));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordFormat", SqlDbType.Int, (int)_passwordFormat));
                                cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, utcNow));

                                // Handle user key (if provided)
                                SqlParameter userIdParam = MembershipDataAccess.CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Users_DeleteUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, username));

                        // Determine the tables to delete from based on the deleteAllRelatedData flag
                        int tablesToDeleteFrom = deleteAllRelatedData ? 15 : 1;
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@TablesToDeleteFrom", SqlDbType.Int, tablesToDeleteFrom));

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
            return _passwordUtility.EncryptPassword(password, legacyPasswordCompatibilityMode);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByEmail", connection)) {
                        MembershipUserCollection usersByEmail = new MembershipUserCollection();
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@EmailToMatch", SqlDbType.NVarChar, emailToMatch));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = MembershipDataAccess.GetNullableString(reader, 0);
                                string email = MembershipDataAccess.GetNullableString(reader, 1);
                                string passwordQuestion = MembershipDataAccess.GetNullableString(reader, 2);
                                string comment = MembershipDataAccess.GetNullableString(reader, 3);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByName", connection)) {
                        MembershipUserCollection usersByName = new MembershipUserCollection();
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserNameToMatch", SqlDbType.NVarChar, usernameToMatch));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = MembershipDataAccess.GetNullableString(reader, 0);
                                string email = MembershipDataAccess.GetNullableString(reader, 1);
                                string passwordQuestion = MembershipDataAccess.GetNullableString(reader, 2);
                                string comment = MembershipDataAccess.GetNullableString(reader, 3);
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

            return PasswordUtility.GeneratePassword(length, numberOfNonAlphanumericCharacters);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetAllUsers", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            while (reader.Read()) {
                                string username = MembershipDataAccess.GetNullableString(reader, 0);
                                string email = MembershipDataAccess.GetNullableString(reader, 1);
                                string passwordQuestion = MembershipDataAccess.GetNullableString(reader, 2);
                                string comment = MembershipDataAccess.GetNullableString(reader, 3);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetNumberOfUsersOnline", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@MinutesSinceLastInActive", SqlDbType.Int, UserIsOnlineTimeWindow));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

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
            string encodedPasswordAnswer = _membershipDataAccess.GetEncodedPasswordAnswer(username, passwordAnswer, ApplicationName, ref _schemaVersionCheck);

            // Validate the encoded password answer parameter
            SecUtility.CheckParameter(ref encodedPasswordAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, 128, nameof(passwordAnswer));

            int passwordFormat = 0;
            int status = 0;

            // Retrieve the password from the database
            string passwordFromDb = _membershipDataAccess.GetPasswordFromDB(username, encodedPasswordAnswer, ApplicationName, MaxInvalidPasswordAttempts, PasswordAttemptWindow, this.RequiresQuestionAndAnswer, out passwordFormat, out status, ref _schemaVersionCheck);

            // If a password was retrieved, unencode it and return
            if (passwordFromDb != null)
                return _passwordUtility.UnEncodePassword(passwordFromDb, passwordFormat);

            // Handle errors based on the status code
            string exceptionText = MembershipValidation.GetExceptionText(status);

            if (MembershipValidation.IsStatusDueToBadPassword(status))
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByUserId", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader()) {
                            if (!reader.Read())
                                return null;

                            string email = MembershipDataAccess.GetNullableString(reader, 0);
                            string passwordQuestion = MembershipDataAccess.GetNullableString(reader, 1);
                            string comment = MembershipDataAccess.GetNullableString(reader, 2);
                            bool isApproved = reader.GetBoolean(3);
                            DateTime creationDate = reader.GetDateTime(4).ToLocalTime();
                            DateTime lastLoginDate = reader.GetDateTime(5).ToLocalTime();
                            DateTime lastActivityDate = reader.GetDateTime(6).ToLocalTime();
                            DateTime lastPasswordChangedDate = reader.GetDateTime(7).ToLocalTime();
                            string userName = MembershipDataAccess.GetNullableString(reader, 8);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByName", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader()) {
                            if (!reader.Read())
                                return null;

                            string email = MembershipDataAccess.GetNullableString(reader, 0);
                            string passwordQuestion = MembershipDataAccess.GetNullableString(reader, 1);
                            string comment = MembershipDataAccess.GetNullableString(reader, 2);
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByEmail", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@Email", SqlDbType.NVarChar, email));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess)) {
                            string userNameByEmail = null;
                            if (reader.Read()) {
                                userNameByEmail = MembershipDataAccess.GetNullableString(reader, 0);
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

            _membershipDataAccess.GetPasswordWithFormat(username, false, ApplicationName, out status, out string _, out passwordFormat, out passwordSalt, out int _, out int _, out bool _, out DateTime _, out DateTime _, ref _schemaVersionCheck);

            if (status != 0) {
                if (MembershipValidation.IsStatusDueToBadPassword(status))
                    throw new Exception(MembershipValidation.GetExceptionText(status));
                throw new ProviderException(MembershipValidation.GetExceptionText(status));
            }

            if (passwordAnswer != null)
                passwordAnswer = passwordAnswer.Trim();

            string encodedPasswordAnswer = string.IsNullOrEmpty(passwordAnswer)
                ? passwordAnswer
                : _passwordUtility.EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, passwordSalt);

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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_ResetPassword", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@NewPassword", SqlDbType.NVarChar, _passwordUtility.EncodePassword(newPassword, passwordFormat, passwordSalt)));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, MaxInvalidPasswordAttempts));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, PasswordAttemptWindow));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, passwordSalt));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordFormat", SqlDbType.Int, passwordFormat));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        if (RequiresQuestionAndAnswer) {
                            cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
                        }

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        int resetStatus = returnValue.Value != null ? (int)returnValue.Value : -1;
                        if (resetStatus == 0)
                            return newPassword;

                        string exceptionText = MembershipValidation.GetExceptionText(resetStatus);
                        if (MembershipValidation.IsStatusDueToBadPassword(resetStatus))
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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UnlockUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, username));

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
                    _membershipDataAccess.CheckSchemaVersion(connection, ref _schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUser", connection)) {
                        cmd.CommandTimeout = CommandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UserName", SqlDbType.NVarChar, user.UserName));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@Email", SqlDbType.NVarChar, user.Email));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@Comment", SqlDbType.NText, user.Comment));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@IsApproved", SqlDbType.Bit, user.IsApproved ? 1 : 0));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@LastLoginDate", SqlDbType.DateTime, user.LastLoginDate.ToUniversalTime()));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@LastActivityDate", SqlDbType.DateTime, user.LastActivityDate.ToUniversalTime()));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@UniqueEmail", SqlDbType.Int, RequiresUniqueEmail ? 1 : 0));
                        cmd.Parameters.Add(MembershipDataAccess.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        int status = returnValue.Value != null ? (int)returnValue.Value : -1;
                        if (status != 0)
                            throw new ProviderException(MembershipValidation.GetExceptionText(status));
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
                _membershipDataAccess.CheckPassword(username, password, true, true, ApplicationName, MaxInvalidPasswordAttempts, PasswordAttemptWindow, ref _schemaVersionCheck)) {
                return true;
            }

            return false;
        }

        protected virtual void OnValidatingPassword(ValidatePasswordEventArgs e)
        {
            if (this._EventHandler == null)
                return;
            this._EventHandler((object)this, e);
        }
    }
}