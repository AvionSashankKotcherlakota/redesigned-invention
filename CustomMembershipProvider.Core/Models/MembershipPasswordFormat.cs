using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Models
{
    public enum MembershipPasswordFormat
    {
        /// <summary>Not secure, do not use. Passwords are not encrypted.</summary>
        Clear,
        /// <summary>Passwords are encrypted one-way using the SHA1 hashing algorithm.</summary>
        Hashed,
        /// <summary>Not secure, do not use. Passwords are encrypted using the encryption settings determined by the machineKey Element (ASP.NET Settings Schema) element configuration.</summary>
        Encrypted,
    }
}
