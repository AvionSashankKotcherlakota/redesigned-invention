using System;
using System.Collections;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace CustomMembershipProvider.Core.Utilities
{
    internal static class SecUtility
    {
        // Method to get the default application name based on the hosting environment
        internal static string GetDefaultAppName()
        {
            try {
                // In .NET Core, we use AppDomain to get the application name
                string appName = AppDomain.CurrentDomain.FriendlyName;
                if (string.IsNullOrEmpty(appName)) {
                    appName = Process.GetCurrentProcess().MainModule.ModuleName;
                    int startIndex = appName.IndexOf('.');
                    if (startIndex != -1)
                        appName = appName.Remove(startIndex);
                }
                return string.IsNullOrEmpty(appName) ? "/" : appName;
            }
            catch {
                return "/";
            }
        }

        // Method to get the connection string from the configuration
        internal static string GetConnectionString(IConfiguration configuration, NameValueCollection config)
        {
            string connectionString = config["connectionString"];
            if (!string.IsNullOrEmpty(connectionString))
                return connectionString;

            string specifiedConnectionString = config["connectionStringName"];
            if (!string.IsNullOrEmpty(specifiedConnectionString)) {
                connectionString = configuration.GetConnectionString(specifiedConnectionString);
                if (!string.IsNullOrEmpty(connectionString))
                    return connectionString;
            }

            throw new ProviderException("Connection string not found or specified.");
        }

        // Method to validate the password parameter
        internal static bool ValidatePasswordParameter(ref string param, int maxSize)
        {
            return param != null && param.Length >= 1 && (maxSize <= 0 || param.Length <= maxSize);
        }

        // Method to validate a parameter with various checks
        internal static bool ValidateParameter(
            ref string param,
            bool checkForNull,
            bool checkIfEmpty,
            bool checkForCommas,
            int maxSize)
        {
            if (param == null)
                return !checkForNull;

            param = param.Trim();
            return (!checkIfEmpty || param.Length >= 1) &&
                   (maxSize <= 0 || param.Length <= maxSize) &&
                   (!checkForCommas || !param.Contains(","));
        }

        // Method to check the validity of a password parameter
        internal static void CheckPasswordParameter(ref string param, int maxSize, string paramName)
        {
            if (param == null)
                throw new ArgumentNullException(paramName);

            if (param.Length < 1)
                throw new ArgumentException($"Parameter {paramName} cannot be empty.");

            if (maxSize > 0 && param.Length > maxSize)
                throw new ArgumentException($"Parameter {paramName} exceeds maximum size of {maxSize} characters.");
        }

        // Method to check the validity of a general parameter
        internal static void CheckParameter(
            ref string param,
            bool checkForNull,
            bool checkIfEmpty,
            bool checkForCommas,
            int maxSize,
            string paramName)
        {
            if (param == null) {
                if (checkForNull)
                    throw new ArgumentNullException(paramName);
            } else {
                param = param.Trim();
                if (checkIfEmpty && param.Length < 1)
                    throw new ArgumentException($"Parameter {paramName} cannot be empty.");

                if (maxSize > 0 && param.Length > maxSize)
                    throw new ArgumentException($"Parameter {paramName} exceeds maximum size of {maxSize} characters.");

                if (checkForCommas && param.Contains(","))
                    throw new ArgumentException($"Parameter {paramName} cannot contain commas.");
            }
        }

        // Method to check the validity of an array parameter
        internal static void CheckArrayParameter(
            ref string[] param,
            bool checkForNull,
            bool checkIfEmpty,
            bool checkForCommas,
            int maxSize,
            string paramName)
        {
            if (param == null)
                throw new ArgumentNullException(paramName);

            Hashtable hashtable = param.Length >= 1 ? new Hashtable(param.Length) : throw new ArgumentException($"Parameter array {paramName} cannot be empty.");

            for (int i = 0; i < param.Length; i++) {
                string paramNameWithIndex = $"{paramName}[ {i} ]";
                CheckParameter(ref param[i], checkForNull, checkIfEmpty, checkForCommas, maxSize, paramNameWithIndex);

                if (hashtable.Contains(param[i]))
                    throw new ArgumentException($"Parameter array {paramName} contains duplicate elements.");

                hashtable.Add(param[i], param[i]);
            }
        }

        // Method to get a boolean value from configuration
        internal static bool GetBooleanValue(IConfiguration configuration, string key, bool defaultValue)
        {
            string value = configuration[key];
            if (string.IsNullOrEmpty(value)) {
                return defaultValue;
            }

            if (bool.TryParse(value, out bool result)) {
                return result;
            }

            throw new ProviderException($"The value for {key} must be a boolean.");
        }


        // Method to get an integer value from configuration
        internal static int GetIntValue(IConfiguration configuration, string key, int defaultValue, bool zeroAllowed, int maxValueAllowed)
        {
            string value = configuration[key];
            if (string.IsNullOrEmpty(value)) {
                return defaultValue;
            }

            if (!int.TryParse(value, out int result)) {
                throw new ProviderException($"The value for {key} must be an integer.");
            }

            if (!zeroAllowed && result <= 0) {
                throw new ProviderException($"{key} must be a positive integer.");
            }

            if (maxValueAllowed > 0 && result > maxValueAllowed) {
                throw new ProviderException($"{key} exceeds the maximum allowed value of {maxValueAllowed}.");
            }

            return result;
        }


        // Method to check schema version
        internal static void CheckSchemaVersion(
            object provider,
            SqlConnection connection,
            string[] features,
            string version,
            ref int schemaVersionCheck)
        {
            if (connection == null)
                throw new ArgumentNullException(nameof(connection));

            if (features == null)
                throw new ArgumentNullException(nameof(features));

            if (version == null)
                throw new ArgumentNullException(nameof(version));

            if (schemaVersionCheck == -1)
                throw new InvalidOperationException($"The schema version for provider {provider?.ToString()} does not match.");

            if (schemaVersionCheck != 0)
                return;

            lock (provider) {
                if (schemaVersionCheck == -1)
                    throw new InvalidOperationException($"The schema version for provider {provider?.ToString()} does not match.");

                if (schemaVersionCheck != 0)
                    return;

                foreach (string feature in features) {
                    using (SqlCommand cmd = new SqlCommand("dbo.aspnet_CheckSchemaVersion", connection)) {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@Feature", feature);
                        cmd.Parameters.AddWithValue("@CompatibleSchemaVersion", version);

                        SqlParameter returnValue = new SqlParameter("@ReturnValue", SqlDbType.Int) {
                            Direction = ParameterDirection.ReturnValue
                        };
                        cmd.Parameters.Add(returnValue);

                        cmd.ExecuteNonQuery();

                        if ((int)returnValue.Value != 0) {
                            schemaVersionCheck = -1;
                            throw new InvalidOperationException($"The schema version for provider {provider?.ToString()} does not match.");
                        }
                    }
                }

                schemaVersionCheck = 1;
            }
        }

    }
}
