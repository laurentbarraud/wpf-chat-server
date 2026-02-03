/// <file>PublicKeyEntry.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 3rd, 2026</date>

using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ChatClient.MVVM.Model
{
    /// <summary>
    /// Represents a single public key entry displayed in the monitor.
    /// Contains raw data and computed validation logic, but no localization.
    /// </summary>
    public class PublicKeyEntry : INotifyPropertyChanged
    {
        private Guid _uid;
        private string _username = string.Empty;
        private string _keyExcerpt = string.Empty;
        private bool _isLocal;
        private string _statusText = string.Empty;

        /// <summary>
        /// Unique identifier of the user this entry refers to.
        /// </summary>
        public Guid UID
        {
            get => _uid;
            set { _uid = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Username associated with this entry.
        /// </summary>
        public string Username
        {
            get => _username;
            set { _username = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Excerpt of the public key (first 20 chars + "....").
        /// Changing this also triggers IsValid.
        /// </summary>
        public string KeyExcerpt
        {
            get => _keyExcerpt;
            set
            {
                _keyExcerpt = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsValid));
            }
        }

        /// <summary>
        /// True when the key is missing or invalid.
        /// Convenience property for readability.
        /// </summary>
        public bool IsMissing => !IsValid;

        /// <summary>
        /// Computed validity: true if the public key excerpt is non-empty.
        /// </summary>
        public bool IsValid => !string.IsNullOrWhiteSpace(KeyExcerpt);

        /// <summary>
        /// True if this entry represents the local client's own key.
        /// </summary>
        public bool IsLocal
        {
            get => _isLocal;
            set { _isLocal = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Localized status text injected by the ViewModel.
        /// </summary>
        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

