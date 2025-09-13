/// <file>UserModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 13th, 2025</date>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace chat_client.MVVM.Model
{
    public class UserModel
    {
        public string Username { get; set; }
        public string UID { get; set; }

        /// <summary>
        /// Stores the user's public key in Base64 format, used for encryption.
        /// </summary>
        public string? PublicKeyBase64 { get; set; }
    }
}
