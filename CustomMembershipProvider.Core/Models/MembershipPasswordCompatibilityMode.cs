using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Models
{
    public enum MembershipPasswordCompatibilityMode
    {
        /// <summary>Passwords are in ASP.NET 2.0 mode.</summary>
        Framework20,
        /// <summary>Passwords are in ASP.NET 4 mode.</summary>
        Framework40,
    }
}
