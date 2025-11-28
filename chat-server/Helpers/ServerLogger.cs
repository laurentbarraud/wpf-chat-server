/// <file>ServerLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 28th, 2025</date>

using System;

namespace chat_server.Helpers
{
    /// <summary>
    /// Defines severity levels for log messages.
    /// </summary>
    public enum ServerLogLevel
    {
        Info,
        Debug,
        Warn,
        Error
    }

    /// <summary>
    /// Provides centralized logging for the server with support for verbosity levels and localization.  
    /// Filters debug messages based on build configuration or runtime flags.  
    /// Supports localized output using resource keys and optional formatting arguments.  
    /// Intended for use across all server components to ensure consistent and maintainable log output.
    /// </summary>
    public static class ServerLogger
    {
        /// <summary>
        /// Indicates whether debug-level logs should be displayed.  
        /// Typically set in Program.cs based on build configuration or command-line arguments.
        /// </summary>
        public static bool IsDebugEnabled { get; set; } = false;

        /// <summary>
        /// Logs a raw message with timestamp and severity prefix.  
        /// Skips debug messages if debug mode is disabled.
        /// </summary>
        /// <param name="message">The message to display.</param>
        /// <param name="level">The severity level of the message.</param>
        public static void Log(string message, ServerLogLevel level = ServerLogLevel.Info)
        {
            if (level == ServerLogLevel.Debug && !IsDebugEnabled)
                return;

            string prefix = level switch
            {
                ServerLogLevel.Info => "[INFO] ",
                ServerLogLevel.Warn => "[WARN] ",
                ServerLogLevel.Error => "[ERROR]",
                ServerLogLevel.Debug => "[DEBUG]",
                _ => "[DEBUG] "
            };

            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
            Console.WriteLine($"{prefix}[{timestamp}] {message}");
        }

        /// <summary>
        /// Logs a localized message using a resource key and up to two optional string arguments.
        /// Retrieves the corresponding template from the LocalizationManager and formats it with the provided values.
        /// Falls back to the key itself if no template is found.
        /// </summary>
        /// <param name="messageKey">The localization key identifying the message template.</param>
        /// <param name="level">The severity level to apply to the log entry.</param>
        /// <param name="arg1">Optional first argument to inject into the template.</param>
        /// <param name="arg2">Optional second argument to inject into the template.</param>
        public static void LogLocalized(string messageKey, ServerLogLevel level, string? arg1 = null, string? arg2 = null)
        {
            var template = LocalizationManager.GetString(messageKey) ?? messageKey;
            var message = string.Format(template, arg1 ?? "", arg2 ?? "");
            Log(message, level);
        }
    }
}
