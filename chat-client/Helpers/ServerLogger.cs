/// <file>ServerLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using chat_client.Helpers;

namespace chat_server.Helpers
{
    public enum LogLevel
    {
        Info,
        Debug,
        Warn,
        Error
    }

    public static class ServerLogger
    {
        // Set to true in Program.cs or via config to enable Debug-level logs
        public static bool IsDebugEnabled { get; set; } = false;

        /// <summary>
        /// Logs a raw message with timestamp and severity prefix.
        /// </summary>
        public static void Log(string message, LogLevel level = LogLevel.Info)
        {
            if (level == LogLevel.Debug && !IsDebugEnabled)
                return;

            string prefix = level switch
            {
                LogLevel.Info => "[INFO] ",
                LogLevel.Warn => "[WARN] ",
                LogLevel.Error => "[ERROR]",
                _ => "[DEBUG]"
            };

            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
            Console.WriteLine($"{prefix}[{timestamp}] {message}");
        }

        /// <summary>
        /// Logs a localized message using a resource key.
        /// </summary>
        public static void LogLocalized(string resourceKey, LogLevel level = LogLevel.Info)
        {
            string message = LocalizationManager.GetString(resourceKey);
            Log(message, level);
        }

        /// <summary>
        /// Logs a formatted localized message with arguments.
        /// </summary>
        public static void LogLocalized(string resourceKey, LogLevel level, params object[] args)
        {
            string template = LocalizationManager.GetString(resourceKey);
            string message = string.Format(template, args);
            Log(message, level);
        }
    }
}
