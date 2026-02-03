/// <file>ChatMessage.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 3rd, 2026</date>

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
        public string Text { get; set; } = string.Empty;
        public string Sender { get; set; } = string.Empty;
        public string TimeStamp { get; set; } = string.Empty;
        public bool IsFromLocalUser { get; set; } = false;
        public bool IsSystemMessage { get; set; } = false;
    }
}
