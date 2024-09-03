using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Utilities
{
    internal static class MembershipHelper
    {
        private static readonly char[] punctuations = "!@#$%^&*()_-+=[{]};:>|./?".ToCharArray();

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
    }
}
