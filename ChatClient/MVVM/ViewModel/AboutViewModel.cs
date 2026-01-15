/// <file>AboutViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

using ChatClient.Helpers;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace ChatClient.MVVM.ViewModel
{
    /// <summary>
    /// ViewModel for the About window.
    /// Provides localized licence information and CLI link text.
    /// Implements INotifyPropertyChanged for UI binding updates.
    /// </summary>
    public class AboutViewModel : INotifyPropertyChanged
    {
        // PRIVATE FIELDS

        /// <summary> Backing fields for localized strings </summary>
        private string _aboutWindowTitle = string.Empty;
        private string _cliArgumentsText = string.Empty;
        private string _licenceInfo = string.Empty;
        private string _licenceInfoResources = string.Empty;
        private string _licenceFinal = string.Empty;
        private bool _hintOfHotspotShown = false;
        
        // PUBLIC PROPERTIES

        /// <summary> Localized text for the about window title. </summary>
        public string AboutWindowTitle
        {
            get => _aboutWindowTitle;
            set
            {
                _aboutWindowTitle = value;
                OnPropertyChanged();
            }
        }

        /// <summary> 
        /// Localized text for the CLI link.
        /// Bound to the TextBlock (CliTextBlock) in the About window.
        /// </summary>
        public string CliArgumentsText
        {
            get => _cliArgumentsText;
            set
            {
                _cliArgumentsText = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Indicates whether the hotspot has already been activated during this window session.
        /// </summary>
        public bool HintOfHotspotShown => _hintOfHotspotShown;

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

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Initializes the ViewModel with localized strings.
        /// </summary>
        public AboutViewModel()
        {
            AboutWindowTitle = LocalizationManager.GetString("AboutThisSoftwareLabel");
            CliArgumentsText = LocalizationManager.GetString("CliArgumentsText");
            LicenceInfo = LocalizationManager.GetString("LicenceInfo");
            LicenceInfoResources = LocalizationManager.GetString("LicenceInfoResources");
            LicenceFinal = LocalizationManager.GetString("LicenceFinal");
        }

        /// <summary>
        /// Helper method that use CallerMemberName to avoid hardcoding property names.
        /// Notifies the UI that a property value has changed.
        /// </summary>
        /// <param name="propertyName">The name of the changed property.</param>
        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Attempts to trigger the hotspot highlight once per window instance.
        /// Returns true when the hint is shown for the first time.
        /// </summary>
        public bool TryShowHotspotHint() 
        {
            if (_hintOfHotspotShown)
            {
                return false;
            }
                
            _hintOfHotspotShown = true; 
            return true; 
        }

        /// <summary> 
        /// Attempts to fade out the hotspot hint if it is currently active.
        /// Returns true when the hint is successfully hidden.
        /// </summary>
        public bool TryHideHotspotHint() 
        {
            if (!_hintOfHotspotShown)
            {
                return false;
            }
            
            _hintOfHotspotShown = false; 
            return true; 
        }
    }
}

