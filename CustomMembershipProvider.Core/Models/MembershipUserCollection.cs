using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomMembershipProvider.Core.Models
{
    /// <summary>
    /// A collection class that stores MembershipUser objects, providing methods to add, remove, and manage users.
    /// </summary>
    [Serializable]
    public sealed class MembershipUserCollection : ICollection<MembershipUser>, IEnumerable<MembershipUser>, IEnumerable
    {
        private Hashtable _Indices;  // Maps usernames to their index in the _Values ArrayList
        private ArrayList _Values;    // Stores the actual MembershipUser objects
        private bool _ReadOnly;       // Indicates if the collection is read-only

        /// <summary>
        /// Initializes a new instance of the MembershipUserCollection class.
        /// </summary>
        public MembershipUserCollection()
        {
            _Indices = new Hashtable(10, StringComparer.CurrentCultureIgnoreCase);
            _Values = new ArrayList();
        }

        /// <summary>
        /// Gets the MembershipUser object with the specified username.
        /// </summary>
        /// <param name="name">The username of the MembershipUser to get.</param>
        /// <returns>The MembershipUser object, or null if not found.</returns>
        public MembershipUser this[string name]
        {
            get {
                object index = _Indices[name];
                if (index == null || !(index is int indexValue))
                    return null;
                return indexValue >= _Values.Count ? null : (MembershipUser)_Values[indexValue];
            }
        }

        /// <summary>
        /// Adds a MembershipUser to the collection.
        /// </summary>
        /// <param name="user">The MembershipUser to add.</param>
        public void Add(MembershipUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (_ReadOnly)
                throw new NotSupportedException();

            int index = _Values.Add(user);  // Add user to _Values ArrayList
            try {
                _Indices.Add(user.UserName, index);  // Add username and index to _Indices Hashtable
            }
            catch {
                _Values.RemoveAt(index);  // If adding to _Indices fails, remove user from _Values
                throw;
            }
        }

        /// <summary>
        /// Removes the MembershipUser with the specified username from the collection.
        /// </summary>
        /// <param name="name">The username of the MembershipUser to remove.</param>
        public void Remove(string name)
        {
            if (_ReadOnly)
                throw new NotSupportedException();

            object index = _Indices[name];
            if (index == null || !(index is int indexValue) || indexValue >= _Values.Count)
                return;

            _Values.RemoveAt(indexValue);  // Remove the user from _Values
            _Indices.Remove(name);  // Remove the username from _Indices

            // Adjust the indices of remaining users in _Indices
            ArrayList keysToUpdate = new ArrayList();
            foreach (DictionaryEntry entry in _Indices) {
                if ((int)entry.Value > indexValue)
                    keysToUpdate.Add(entry.Key);
            }

            foreach (string key in keysToUpdate) {
                _Indices[key] = (int)_Indices[key] - 1;
            }
        }

        /// <summary>
        /// Clears all users from the collection.
        /// </summary>
        public void Clear()
        {
            if (_ReadOnly)
                throw new NotSupportedException();
            _Values.Clear();  // Clear the _Values list
            _Indices.Clear();  // Clear the _Indices hashtable
        }

        /// <summary>
        /// Marks the collection as read-only.
        /// </summary>
        public void SetReadOnly()
        {
            if (_ReadOnly)
                return;

            _ReadOnly = true;  // Set the collection to read-only
            _Values = ArrayList.ReadOnly(_Values);  // Make the _Values list read-only
        }

        /// <summary>
        /// Gets the number of MembershipUser objects in the collection.
        /// </summary>
        public int Count => _Values.Count;

        /// <summary>
        /// Gets a value indicating whether access to the collection is synchronized (thread-safe).
        /// </summary>
        public bool IsSynchronized => false;

        /// <summary>
        /// Gets an object that can be used to synchronize access to the collection.
        /// </summary>
        public object SyncRoot => this;

        /// <summary>
        /// Copies the elements of the collection to a MembershipUser array, starting at a particular array index.
        /// </summary>
        /// <param name="array">The array to copy to.</param>
        /// <param name="index">The zero-based index at which to start copying.</param>
        public void CopyTo(MembershipUser[] array, int index)
        {
            _Values.CopyTo(array, index);  // Copy _Values to the provided array
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An IEnumerator of MembershipUser objects.</returns>
        public IEnumerator<MembershipUser> GetEnumerator()
        {
            foreach (MembershipUser user in _Values) {
                yield return user;  // Return each MembershipUser in _Values
            }
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An IEnumerator for the collection.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return _Values.GetEnumerator();  // Return enumerator for _Values
        }

        /// <summary>
        /// Determines whether the collection contains a specific MembershipUser.
        /// </summary>
        /// <param name="user">The MembershipUser to locate in the collection.</param>
        /// <returns>True if the user is found in the collection; otherwise, false.</returns>
        public bool Contains(MembershipUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return _Indices.ContainsKey(user.UserName);
        }

        /// <summary>
        /// Removes the specified MembershipUser from the collection.
        /// </summary>
        /// <param name="user">The MembershipUser to remove.</param>
        /// <returns>True if the user was successfully removed; otherwise, false.</returns>
        public bool Remove(MembershipUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (_ReadOnly)
                throw new NotSupportedException();

            if (_Indices.ContainsKey(user.UserName)) {
                Remove(user.UserName);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Gets a value indicating whether the collection is read-only.
        /// </summary>
        public bool IsReadOnly => _ReadOnly;
    }
}
