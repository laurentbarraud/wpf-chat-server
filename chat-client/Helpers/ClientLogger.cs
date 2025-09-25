/// <file>ClientLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using chat_client.Helpers;

namespace ChatClient.Helpers
{
    public enum LogLevel
    {
        Info,
        Debug,
        Warn,
        Error
    }

    public static class ClientLogger
    {
        // Set to true to enable verbose debug output
        public static bool IsDebugEnabled { get; set; } = false;

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

        public static void LogLocalized(string resourceKey, LogLevel level = LogLevel.Info)
        {
            string message = LocalizationManager.GetString(resourceKey);
            Log(message, level);
        }
    }
}

