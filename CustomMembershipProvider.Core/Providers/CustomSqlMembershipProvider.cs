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

namespace CustomMembershipProvider.Core.Providers
{
    public class CustomSqlMembershipProvider : ICustomSqlMembershipProvider
    {
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
        public CustomSqlMembershipProvider(IConfiguration configuration, string connectionStringName)
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


        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
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
                                cmd.Parameters.Add(CreateInputParam("@PasswordFormat", SqlDbType.Int, (int)_PasswordFormat));
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
            throw new NotImplementedException();
        }

        public MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public string GeneratePassword()
        {
            throw new NotImplementedException();
        }

        public MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        public string GetPassword(string username, string passwordAnswer)
        {
            throw new NotImplementedException();
        }

        public MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        public MembershipUser GetUser(string username, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        public string GetUserNameByEmail(string email)
        {
            throw new NotImplementedException();
        }

        public void Initialize(string name, NameValueCollection config)
        {
            throw new NotImplementedException();
        }

        public string ResetPassword(string username, string passwordAnswer)
        {
            throw new NotImplementedException();
        }

        public bool UnlockUser(string username)
        {
            throw new NotImplementedException();
        }

        public void UpdateUser(MembershipUser user)
        {
            throw new NotImplementedException();
        }

        public bool ValidateUser(string username, string password)
        {
            throw new NotImplementedException();
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

        private string EncodePassword(string password, int format, string salt)
        {
            if (format == 0) // Clear
            {
                return password;
            } else if (format == 1) // Hashed
              {
                using (SHA1 hash = SHA1.Create()) {
                    byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
                    byte[] saltBytes = Convert.FromBase64String(salt);
                    byte[] combinedBytes = new byte[saltBytes.Length + passwordBytes.Length];
                    Buffer.BlockCopy(saltBytes, 0, combinedBytes, 0, saltBytes.Length);
                    Buffer.BlockCopy(passwordBytes, 0, combinedBytes, saltBytes.Length, passwordBytes.Length);
                    byte[] hashBytes = hash.ComputeHash(combinedBytes);
                    return Convert.ToBase64String(hashBytes);
                }
            } else {
                throw new ProviderException("Unsupported password format.");
            }
        }

        private bool GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, out string password, out string salt, out int passwordFormat, out bool isApproved)
        {
            password = null;
            salt = null;
            passwordFormat = 0;
            isApproved = false;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();
                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetPasswordWithFormat", connection)) {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@ApplicationName", ApplicationName);
                        cmd.Parameters.AddWithValue("@UserName", username);
                        cmd.Parameters.AddWithValue("@UpdateLastLoginActivityDate", updateLastLoginActivityDate);
                        cmd.Parameters.AddWithValue("@CurrentTimeUtc", DateTime.UtcNow);

                        SqlParameter passwordParam = new SqlParameter("@Password", SqlDbType.NVarChar, 128) { Direction = ParameterDirection.Output };
                        SqlParameter saltParam = new SqlParameter("@PasswordSalt", SqlDbType.NVarChar, 128) { Direction = ParameterDirection.Output };
                        SqlParameter passwordFormatParam = new SqlParameter("@PasswordFormat", SqlDbType.Int) { Direction = ParameterDirection.Output };
                        SqlParameter isApprovedParam = new SqlParameter("@IsApproved", SqlDbType.Bit) { Direction = ParameterDirection.Output };

                        cmd.Parameters.Add(passwordParam);
                        cmd.Parameters.Add(saltParam);
                        cmd.Parameters.Add(passwordFormatParam);
                        cmd.Parameters.Add(isApprovedParam);

                        using (SqlDataReader reader = cmd.ExecuteReader(CommandBehavior.SingleRow)) {
                            if (reader.Read()) {
                                password = reader.GetString(0);
                                salt = reader.GetString(1);
                                passwordFormat = reader.GetInt32(2);
                                isApproved = reader.GetBoolean(3);
                            }
                        }

                        // Check if the retrieved data is valid
                        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(salt)) {
                            return false;
                        }

                        return true;
                    }
                }
            }
            catch (Exception ex) {
                throw new ProviderException("Error retrieving password with format.", ex);
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
            salt = null;
            passwordFormat = 0;

            // Validate parameters using SecUtility
            SecUtility.CheckParameter(ref username, true, true, true, 256, nameof(username));
            SecUtility.CheckParameter(ref password, true, true, false, 128, nameof(password));

            // Retrieve the password with its format
            string storedPassword;
            bool isApproved;
            DateTime lastLoginDate = DateTime.MinValue;
            DateTime lastActivityDate = DateTime.MinValue;

            if (!GetPasswordWithFormat(username, updateLastLoginActivityDate, out storedPassword, out salt, out passwordFormat, out isApproved)) {
                return false;  // Failed to retrieve password information
            }

            // Check if the user is approved
            if (failIfNotApproved && !isApproved) {
                return false;
            }

            // Encode the provided password using the retrieved salt and format
            string encodedPassword = EncodePassword(password, passwordFormat, salt);

            // Compare the stored password with the encoded password
            bool passwordsMatch = storedPassword.Equals(encodedPassword);

            if (updateLastLoginActivityDate) {
                try {
                    DateTime utcNow = DateTime.UtcNow;
                    using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                        connection.Open();
                        using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUserInfo", connection)) {
                            cmd.CommandType = CommandType.StoredProcedure;

                            cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                            cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                            cmd.Parameters.Add(CreateInputParam("@IsPasswordCorrect", SqlDbType.Bit, passwordsMatch));
                            cmd.Parameters.Add(CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
                            cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, MaxInvalidPasswordAttempts));
                            cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, PasswordAttemptWindow));
                            cmd.Parameters.Add(CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, utcNow));
                            cmd.Parameters.Add(CreateInputParam("@LastLoginDate", SqlDbType.DateTime, passwordsMatch ? utcNow : lastLoginDate));
                            cmd.Parameters.Add(CreateInputParam("@LastActivityDate", SqlDbType.DateTime, passwordsMatch ? utcNow : lastActivityDate));

                            SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                            cmd.Parameters.Add(returnValue);

                            cmd.ExecuteNonQuery();

                            int result = (int)returnValue.Value;
                            if (result != 0) {
                                throw new ProviderException("Failed to update user info.");
                            }
                        }
                    }
                }
                catch (Exception ex) {
                    throw new ProviderException("Error updating user info.", ex);
                }
            }

            return passwordsMatch;
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