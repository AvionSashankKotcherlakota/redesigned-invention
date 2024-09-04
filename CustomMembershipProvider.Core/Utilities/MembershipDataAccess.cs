using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration.Provider;
using CustomMembershipProvider.Core.Interfaces;
using System.Globalization;
using System.Configuration;
using Microsoft.Extensions.Configuration;

namespace CustomMembershipProvider.Core.Utilities
{
    public class MembershipDataAccess : IMembershipDataAccess
    {
        private readonly string _sqlConnectionString;
        private readonly int _commandTimeout;
        private readonly IPasswordUtility _passwordUtility;

        // Constructor accepting the connection string
        public MembershipDataAccess(IConfiguration configuration, IPasswordUtility passwordUtility)
        {
            _sqlConnectionString = configuration.GetConnectionString("DefaultConnection");
            _commandTimeout = configuration.GetValue<int>("MembershipSettings:CommandTimeout", 30);
            _passwordUtility = passwordUtility;
        }

        public void GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, string applicationName, out int status, out string password, out int passwordFormat, out string passwordSalt,
                                        out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate, ref int schemaVersionCheck)
        {
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection, ref schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetPasswordWithFormat", connection)) {
                        cmd.CommandTimeout = _commandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, applicationName));
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

        public string GetPasswordFromDB(string username, string passwordAnswer, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, bool requiresQuestionAndAnswer, out int passwordFormat, out int status, ref int schemaVersionCheck)
        {
            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    CheckSchemaVersion(connection, ref schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetPassword", connection)) {
                        cmd.CommandTimeout = _commandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, applicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, maxInvalidPasswordAttempts));
                        cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, passwordAttemptWindow));
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

        public bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, out string salt, out int passwordFormat, ref int schemaVersionCheck)
        {
            // Retrieve the stored password information
            this.GetPasswordWithFormat(username, updateLastLoginActivityDate, applicationName, out int status, out string storedPassword, out passwordFormat, out salt,
                out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate, ref schemaVersionCheck);

            // Check if the status is not successful or the user is not approved and failIfNotApproved is true
            if (status != 0 || (!isApproved && failIfNotApproved))
                return false;

            // Encode the provided password with the same format and salt used for the stored password
            string encodedPassword = _passwordUtility.EncodePassword(password, passwordFormat, salt);

            // Compare the encoded password with the stored password
            bool isPasswordCorrect = storedPassword.Equals(encodedPassword);

            // If the password is correct and there are no failed attempts, return true
            if (isPasswordCorrect && failedPasswordAttemptCount == 0 && failedPasswordAnswerAttemptCount == 0)
                return true;

            try {
                using (SqlConnection connection = new SqlConnection(_sqlConnectionString)) {
                    connection.Open();

                    // Check schema version
                    this.CheckSchemaVersion(connection, ref schemaVersionCheck);

                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUserInfo", connection)) {
                        DateTime utcNow = DateTime.UtcNow;
                        cmd.CommandTimeout = _commandTimeout;
                        cmd.CommandType = CommandType.StoredProcedure;

                        // Add parameters to the stored procedure
                        cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, applicationName));
                        cmd.Parameters.Add(CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                        cmd.Parameters.Add(CreateInputParam("@IsPasswordCorrect", SqlDbType.Bit, isPasswordCorrect));
                        cmd.Parameters.Add(CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
                        cmd.Parameters.Add(CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, maxInvalidPasswordAttempts));
                        cmd.Parameters.Add(CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, passwordAttemptWindow));
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

        public bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, string applicationName, int maxInvalidPasswordAttempts, int passwordAttemptWindow, ref int schemaVersionCheck)
        {
            return CheckPassword(username, password, updateLastLoginActivityDate, failIfNotApproved, applicationName, maxInvalidPasswordAttempts, passwordAttemptWindow, out string _, out int _, ref schemaVersionCheck);
        }

        public void CheckSchemaVersion(SqlConnection connection, ref int schemaVersionCheck)
        {
            string[] features = new string[2]
            {
                "Common",
                "Membership"
            };
            string version = "1";
            SecUtility.CheckSchemaVersion(this, connection, features, version, ref schemaVersionCheck);
        }

        public string GetEncodedPasswordAnswer(string username, string passwordAnswer, string applicationName, ref int schemaVersionCheck)
        {
            if (passwordAnswer != null)
                passwordAnswer = passwordAnswer.Trim();

            if (string.IsNullOrEmpty(passwordAnswer))
                return passwordAnswer;

            int status;
            int passwordFormat;
            string passwordSalt;

            // Get the password information including salt, format, etc.
            GetPasswordWithFormat(username, false, applicationName, out status, out string _, out passwordFormat, out passwordSalt, out int _, out int _, out bool _, out DateTime _, out DateTime _, ref schemaVersionCheck);

            // If the status indicates success, encode the password answer using the format and salt
            if (status == 0)
                return _passwordUtility.EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, passwordSalt);

            // If status is not successful, throw an exception with the appropriate message
            throw new ProviderException(MembershipValidation.GetExceptionText(status));
        }

        public static string GetNullableString(SqlDataReader reader, int col)
        {
            return !reader.IsDBNull(col) ? reader.GetString(col) : null;
        }

        public static SqlParameter CreateInputParam(string paramName, SqlDbType dbType, object objValue)
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
    }
}
