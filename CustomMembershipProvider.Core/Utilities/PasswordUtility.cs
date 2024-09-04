using CustomMembershipProvider.Core.Interfaces;
using CustomMembershipProvider.Core.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Configuration.Provider;
using System.Globalization;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Utilities
{
    public class PasswordUtility : IPasswordUtility
    {
        private readonly IDataProtector _protector;
        private string? _hashAlgorithmType;
        private int _passwordSaltLength;
        private MembershipPasswordCompatibilityMode _legacyPasswordCompatibilityMode;

        private static readonly char[] punctuations = "!@#$%^&*()_-+=[{]};:>|./?".ToCharArray();

        public PasswordUtility(IDataProtectionProvider dataProtectionProvider, IConfiguration configuration)
        {
            _protector = dataProtectionProvider.CreateProtector("CustomSqlMembershipProvider");

            var securitySettings = configuration.GetSection("SecuritySettings");
            _hashAlgorithmType = securitySettings.GetValue<string>("HashAlgorithmType", "SHA1");
            _passwordSaltLength = securitySettings.GetValue<int>("PasswordSaltLength", 16);

            var membershipSettings = configuration.GetSection("MembershipSettings");
            string passwordCompatMode = membershipSettings.GetValue<string>("PasswordCompatMode", "Framework20");
            _legacyPasswordCompatibilityMode = (MembershipPasswordCompatibilityMode)Enum.Parse(typeof(MembershipPasswordCompatibilityMode), passwordCompatMode);
        }

        public HashAlgorithm GetHashAlgorithm()
        {
            if (!string.IsNullOrEmpty(_hashAlgorithmType)) {
                return HashAlgorithm.Create(_hashAlgorithmType);
            }

            // Default to SHA1 if no valid hash algorithm type is provided
            string hashName = "SHA1";

            if (_legacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework20) {
                hashName = "SHA1"; // Default to SHA1 for Framework 2.0 compatibility
            }

            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashName);

            if (hashAlgorithm == null) {
                throw new InvalidOperationException($"The hash algorithm '{hashName}' could not be created.");
            }

            return hashAlgorithm;
        }

        public static string GeneratePassword(int length, int numberOfNonAlphanumericCharacters)
        {
            if (length < 1 || length > 128)
                throw new ArgumentException("Password length must be between 1 and 128 characters.");
            if (numberOfNonAlphanumericCharacters > length || numberOfNonAlphanumericCharacters < 0)
                throw new ArgumentException("The number of non-alphanumeric characters must be between 0 and the length of the password.");

            string password;
            do {
                byte[] data = new byte[length];
                char[] chars = new char[length];
                int nonAlphanumericCount = 0;

                using (var rng = new RNGCryptoServiceProvider()) {
                    rng.GetBytes(data);
                }

                for (int i = 0; i < length; i++) {
                    int value = data[i] % 87;

                    if (value < 10) {
                        chars[i] = (char)(48 + value); // 0-9
                    } else if (value < 36) {
                        chars[i] = (char)(65 + value - 10); // A-Z
                    } else if (value < 62) {
                        chars[i] = (char)(97 + value - 36); // a-z
                    } else {
                        chars[i] = punctuations[value - 62]; // Punctuation
                        nonAlphanumericCount++;
                    }
                }

                if (nonAlphanumericCount < numberOfNonAlphanumericCharacters) {
                    Random random = new Random();
                    for (int i = 0; i < numberOfNonAlphanumericCharacters - nonAlphanumericCount; i++) {
                        int index;
                        do {
                            index = random.Next(0, length);
                        }
                        while (!char.IsLetterOrDigit(chars[index]));

                        chars[index] = punctuations[random.Next(0, punctuations.Length)];
                    }
                }

                password = new string(chars);
            }
            while (CrossSiteScriptingValidation.IsDangerousString(password, out _));

            return password;
        }

        public string GenerateSalt()
        {
            byte[] buffer = new byte[_passwordSaltLength];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) {
                rng.GetBytes(buffer);
            }
            return Convert.ToBase64String(buffer);
        }

        public string EncodePassword(string pass, int passwordFormat, string salt)
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

        private static byte[] GetKeyedHashKey(KeyedHashAlgorithm algorithm, byte[] salt)
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

        private static byte[] CombineBytes(byte[] first, byte[] second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }

        public string UnEncodePassword(string pass, int passwordFormat)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
                return pass;

            if (passwordFormat == 1) // MembershipPasswordFormat.Hashed
                throw new ProviderException("Cannot decode a hashed password.");

            byte[] decodedBytes = DecryptPassword(Convert.FromBase64String(pass));
            return decodedBytes != null ? Encoding.Unicode.GetString(decodedBytes, 16, decodedBytes.Length - 16) : null;
        }

        public byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode)
        {
            return EncryptOrDecryptData(true, password, legacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework20);
        }

        public byte[] DecryptPassword(byte[] encodedPassword)
        {
            try {
                return EncryptOrDecryptData(false, encodedPassword, false);
            }
            catch {
                throw new ProviderException("Error decrypting password.");
            }
        }

        private byte[] EncryptPassword(byte[] password)
        {
            return EncryptPassword(password, MembershipPasswordCompatibilityMode.Framework20);
        }

        private byte[] EncryptOrDecryptData(bool encrypt, byte[] buffer, bool useLegacyMode)
        {
            if (encrypt) {
                return _protector.Protect(buffer);
            } else {
                return _protector.Unprotect(buffer);
            }
        }
    }
}
