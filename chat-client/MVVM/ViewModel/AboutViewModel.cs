/// <file>AboutViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 22th, 2025</date>

using chat_client.Helpers;
using System;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace chat_client.MVVM.ViewModel
{
    /// <summary>
    /// ViewModel for the About window.
    /// Provides localized licence information split into two parts
    /// (static text and animated name), plus the CLI link text.
    /// Implements INotifyPropertyChanged for UI binding updates.
    /// </summary>
    public class AboutViewModel : INotifyPropertyChanged
    {
        // Backing field for the trimmed licence text (without the appended name part)
        private string _licenceTrimmed;

        // Backing field for the name portion extracted from the full licence string
        private string _licenceName;

        // Backing field for the localized CLI link text
        private string _cliText;

        /// <summary>
        /// Exposes the licence text without the trailing name.
        /// Bound to the UI Run element to display the static part.
        /// </summary>
        public string LicenceTrimmed
        {
            get => _licenceTrimmed; // Returns current value
            set
            {
                _licenceTrimmed = value;       // Updates backing field
                OnPropertyChanged();           // Notifies UI binding of the change
            }
        }

        /// <summary>
        /// Exposes the name portion extracted from the licence.
        /// Bound to the UI TextBlock for animation.
        /// </summary>
        public string LicenceName
        {
            get => _licenceName; 
            set
            {
                _licenceName = value;          
                OnPropertyChanged();           
            }
        }

        /// <summary>
        /// Exposes the localized text for the CLI link.
        /// Bound to the UI TextBlock (CliTextBlock) in the bottom panel.
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

        public AboutViewModel()
        {
            // Full localized string
            string licenceFull = LocalizationManager.GetString("LicenceFinal");

            // Retrieves author from assembly metadata
            var assembly = Assembly.GetExecutingAssembly();
            var companyAttr = assembly.GetCustomAttribute<AssemblyCompanyAttribute>();
            string author = companyAttr?.Company ?? "%author%";

            // Defines the name part dynamically
            string namePart = " " + author;

            // Splits into two parts
            LicenceTrimmed = licenceFull.Substring(0, licenceFull.Length - namePart.Length);
            LicenceName = namePart;

            // Localized CLI link text
            CliText = LocalizationManager.GetString("CommandLineArguments");
        }

        /// <summary>
        /// Event raised when a property value changes.
        /// Required for INotifyPropertyChanged implementation.
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Helper method to raise PropertyChanged events.
        /// Uses CallerMemberName to avoid hardcoding property names.
        /// </summary>
        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
