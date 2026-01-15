/// <file>PublicKeyEntry.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

using System;

namespace ChatClient.MVVM.Model
{
    /// <summary>
    /// Represents a single public key entry displayed in the monitor.
    /// Contains raw data and computed validation logic, but no localization.
    /// </summary>
    public class PublicKeyEntry
    {
        /// <summary> 
        /// Unique identifier of the user this entry refers to.
        /// Used to request the missing public key from the correct peer.
        /// </summary> 
        public Guid UID { get; set; }

        /// <summary> 
        /// Username associated with this public key entry. 
        /// </summary> 
        public string Username { get; set; } = string.Empty; 
        
        /// <summary> 
        /// Excerpt of the public key (first 20 chars + "...."). 
        /// </summary> 
        public string KeyExcerpt { get; set; } = string.Empty;

        /// <summary>
        /// True if the key excerpt is non-empty and appears valid.
        /// This is a computed property; no state is stored.
        /// </summary>
        public bool IsValid => !string.IsNullOrWhiteSpace(KeyExcerpt);

        /// <summary> 
        /// Indicates whether this entry represents the local client's own key. 
        /// </summary> 
        public bool IsLocal { get; set; }

        /// <summary>
        /// Localized status text injected by the ViewModel.
        /// </summary>
        public string StatusText { get; set; } = string.Empty;
    }
}
