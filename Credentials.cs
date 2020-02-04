using Meziantou.Framework.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BasicTOTPs
{
    class Credentials
    {

        public static String key { get; private set; }
        public static String iv { get; private set; }

        public static String decrypt(String bodyToDecrypt)
        {
            using (Rijndael myRijndael = Rijndael.Create())
            {
                myRijndael.Key = OtpNet.Base32Encoding.ToBytes(key);
                myRijndael.IV = OtpNet.Base32Encoding.ToBytes(iv);
                return DecryptStringFromBytes(OtpNet.Base32Encoding.ToBytes(bodyToDecrypt), myRijndael.Key, myRijndael.IV);
            }
        }

        public static String encrypt(String bodyToEncrypt)
        {
            using (Rijndael myRijndael = Rijndael.Create())
            {
                myRijndael.Key = OtpNet.Base32Encoding.ToBytes(key);
                myRijndael.IV = OtpNet.Base32Encoding.ToBytes(iv);
                byte[] encrypted = EncryptStringToBytes(bodyToEncrypt, myRijndael.Key, myRijndael.IV);
                return OtpNet.Base32Encoding.ToString(encrypted);
            }
        }

        public static void saveCredentials(String keyToSave, String ivToSave)
        {
            CredentialManager.WriteCredential(
                applicationName: "BasicTOTPs",
                userName: ivToSave,
                secret: keyToSave,
                comment: "CLI tool for TOTP authentication",
                persistence: CredentialPersistence.LocalMachine);
        }

        public static void loadCredentials()
        {
            var cred = CredentialManager.ReadCredential(applicationName: "BasicTOTPs");
            if (cred != null)
            {
                iv = cred.UserName;
                key = cred.Password;
            }
            else
            {
                // no values found, let's initialize and save
                using (Rijndael myRijndael = Rijndael.Create())
                {
                    key = OtpNet.Base32Encoding.ToString(myRijndael.Key);
                    iv = OtpNet.Base32Encoding.ToString(myRijndael.IV);
                    saveCredentials(key, iv);
                }
            }
        } 


        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

    }
}
