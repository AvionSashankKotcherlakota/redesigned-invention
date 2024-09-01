using CustomMembershipProvider.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Providers
{
    public delegate void MembershipValidatePasswordEventHandler(object sender, ValidatePasswordEventArgs e);
}
