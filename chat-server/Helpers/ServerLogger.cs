/// <file>ServerLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;

namespace chat_server.Helpers
{
    /// <summary>
    /// Defines severity levels for log messages.
    /// </summary>
    public enum LogLevel
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
    public static class ServerLogHelper
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
        public static void Log(string message, LogLevel level = LogLevel.Info)
        {
            if (level == LogLevel.Debug && !IsDebugEnabled)
                return;

            string prefix = level switch
            {
                LogLevel.Info => "[INFO] ",
                LogLevel.Warn => "[WARN] ",
                LogLevel.Error => "[ERROR]",
                _ => "[DEBUG] "
            };

            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
            Console.WriteLine($"{prefix}[{timestamp}] {message}");
        }

        /// <summary>
        /// Logs a localized message using a resource key and optional formatting arguments.  
        /// Retrieves the message from the LocalizationManager and applies the appropriate log level.
        /// </summary>
        /// <param name="resourceKey">The key used to retrieve the localized string template.</param>
        /// <param name="level">The severity level of the message.</param>
        /// <param name="args">Optional arguments to format into the localized string.</param>
        public static void LogLocalized(string resourceKey, LogLevel level = LogLevel.Info, params object[] args)
        {
            string template = LocalizationManager.GetString(resourceKey);
            string message = args.Length > 0 ? string.Format(template, args) : template;
            Log(message, level);
        }
    }
}
