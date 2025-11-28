/// <file>AboutViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 28th, 2025</date>

using chat_client.Helpers;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace chat_client.MVVM.ViewModel
{
    /// <summary>
    /// ViewModel for the About window.
    /// Provides localized licence information and CLI link text.
    /// Implements INotifyPropertyChanged for UI binding updates.
    /// </summary>
    public class AboutViewModel : INotifyPropertyChanged
    {
        // Backing fields for localized strings
        private string _cliText = string.Empty;
        private string _licenceInfo = string.Empty;
        private string _licenceInfoResources = string.Empty;
        private string _licenceFinal = string.Empty;

        /// <summary>
        /// Localized text for the CLI link.
        /// Bound to the TextBlock (CliTextBlock) in the About window.
        /// </summary>
        public string CliText
        {
            get => _cliText;
            set
            {
                _cliText = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Localized licence information text.
        /// Bound to LicenceInfoText in the About window.
        /// </summary>
        public string LicenceInfo
        {
            get => _licenceInfo;
            set
            {
                _licenceInfo = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Localized licence resources text.
        /// Bound to LicenceInfoResourcesText in the About window.
        /// </summary>
        public string LicenceInfoResources
        {
            get => _licenceInfoResources;
            set
            {
                _licenceInfoResources = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Localized final licence text.
        /// Bound to LicenceFinalBlock in the About window.
        /// </summary>
        public string LicenceFinal
        {
            get => _licenceFinal;
            set
            {
                _licenceFinal = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Initializes the ViewModel with localized strings.
        /// </summary>
        public AboutViewModel()
        {
            CliText = LocalizationManager.GetString("CommandLineArguments");
            LicenceInfo = LocalizationManager.GetString("LicenceInfo");
            LicenceInfoResources = LocalizationManager.GetString("LicenceInfoResources");
            LicenceFinal = LocalizationManager.GetString("LicenceFinal");
        }

        /// <summary>
        /// Event raised when a property value changes.
        /// Required for INotifyPropertyChanged implementation.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged = delegate { };

        /// <summary>
        /// Helper method to raise PropertyChanged events.
        /// Uses CallerMemberName to avoid hardcoding property names.
        /// </summary>
        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

