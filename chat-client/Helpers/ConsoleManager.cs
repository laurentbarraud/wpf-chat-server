/// <file>ConsoleManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 3rd, 2025</date>

using System;
using System.Runtime.InteropServices;

namespace chat_client.Helpers
{
    public static class ConsoleManager
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        public static void Show()
        {
            AllocConsole();
            ClientLogger.Log("[Console] Debug console activated.", ClientLogLevel.Info);
        }
    }
}

