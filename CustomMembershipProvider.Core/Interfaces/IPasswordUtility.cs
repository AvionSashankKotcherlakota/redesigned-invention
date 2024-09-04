using CustomMembershipProvider.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Interfaces
{
    public interface IPasswordUtility
    {
        byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode);
        byte[] DecryptPassword(byte[] encodedPassword);
        string EncodePassword(string pass, int passwordFormat, string salt);
        string UnEncodePassword(string pass, int passwordFormat);
        string GenerateSalt();
    }
}
