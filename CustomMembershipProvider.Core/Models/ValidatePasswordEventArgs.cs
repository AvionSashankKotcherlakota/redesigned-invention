using System;

namespace CustomMembershipProvider.Core.Models
{
    public class ValidatePasswordEventArgs : EventArgs
    {
        // Properties
        public string Username { get; }
        public string Password { get; }
        public bool IsNewUser { get; }
        public bool Cancel { get; set; }
        public Exception FailureInformation { get; set; }

        // Constructor
        public ValidatePasswordEventArgs(string username, string password, bool isNewUser)
        {
            Username = username;
            Password = password;
            IsNewUser = isNewUser;
            Cancel = false; // Default to false, meaning don't cancel by default
        }
    }
}