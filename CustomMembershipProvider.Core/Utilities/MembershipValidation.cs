using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Utilities
{
    internal class MembershipValidation
    {
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

        internal static bool IsStatusDueToBadPassword(int status)
        {
            return (status >= 2 && status <= 6) || status == 99;
        }
    }

}
