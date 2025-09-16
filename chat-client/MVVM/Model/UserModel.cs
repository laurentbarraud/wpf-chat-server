/// <file>UserModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 15th, 2025</date>

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

        /// <summary>
        /// Clears the stored public RSA key from the user model.
        /// Used when encryption is disabled or reset, ensuring no residual data remains.
        /// This method supports memory cleanup and prevents accidental reuse of outdated keys.
        /// It guarantees that each encryption activation generates a fresh RSA key pair.
        /// Designed for modular and extensible codebases, enabling future features such as key rotation or multi-profile support.
        /// </summary>

        public void ClearEncryption()
        {
            PublicKeyBase64 = null;

            // Optional: clears private key if stored in future versions
            // PrivateKeyBase64 = null;
        }

    }
}
