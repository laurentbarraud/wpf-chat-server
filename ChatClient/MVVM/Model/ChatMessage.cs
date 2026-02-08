/// <file>ChatMessage.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 8th, 2026</date>

using ChatClient.Helpers;
using Microsoft.VisualBasic.ApplicationServices;
using System;

namespace ChatClient.MVVM.Model
{
    /// <summary>
    /// Represents a chat message prepared for UI display.
    /// Stores the final text shown to the user, the sender's display name,
    /// a timestamp for visual context, and flags indicating whether the
    /// message originates from the local user or represents a system event.
    /// </summary>
    public class ChatMessage
    {
        /// <summary> 
        /// Returns the raw-text representation of the message, 
        /// used when the user activates raw-text mode. 
        /// </summary>
        public string FormattedRawText
        {
            get
            {
                if (IsSystemMessage)
                {
                    // System messages follow the "# Serveur : message" convention.
                    return $"{LocalizationManager.GetString("ServerPrefix")} : {Text}";
                }

                // Standard user messages follow the "Pseudo : message" format.
                return $"{Sender} : {Text}";
            }
        }

        public bool IsFromLocalUser { get; set; } = false;
        public bool IsSystemMessage { get; set; } = false;
        public string Sender { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
        public string TimeStamp { get; set; } = string.Empty;
    }
}
