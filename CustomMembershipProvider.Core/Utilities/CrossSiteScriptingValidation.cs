using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Utilities
{
    internal static class CrossSiteScriptingValidation
    {
        private static readonly char[] startingChars = { '<', '&' };

        internal static bool IsDangerousString(string s, out int matchIndex)
        {
            matchIndex = 0;
            int startIndex = 0;
            while (true) {
                int index = s.IndexOfAny(startingChars, startIndex);
                if (index >= 0 && index != s.Length - 1) {
                    matchIndex = index;
                    switch (s[index]) {
                        case '&':
                            if (s[index + 1] != '#')
                                break;
                            return true;

                        case '<':
                            if (IsAtoZ(s[index + 1]) || s[index + 1] == '!' || s[index + 1] == '/' || s[index + 1] == '?')
                                return true;
                            break;
                    }
                    startIndex = index + 1;
                } else {
                    break;
                }
            }
            return false;
        }

        private static bool IsAtoZ(char c)
        {
            return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
        }
    }

}
