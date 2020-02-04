using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using OtpNet;

namespace BasicTOTPs
{
    class Program
    {

        private static readonly List<Authenticator> authenticators = new List<Authenticator>();
        private static readonly String DELIMITER = "=^.-=";

        static void Main(string[] args)
        {
            Console.WriteLine("Yooooooooooooo! Add a TOTP or retrieve a value for one.");
            Credentials.loadCredentials();
            try
            {
                using (StreamReader sr = new StreamReader("basicTOTPs.db"))
                {
                    try
                    {
                        String line;
                        while (!sr.EndOfStream)
                        {
                            // read from file
                            line = sr.ReadLine();
                            String[] split = line.Split(DELIMITER);
                            Authenticator anAuthenticator = new Authenticator();
                            anAuthenticator.description = Credentials.decrypt(split[0]);
                            anAuthenticator.secret = Credentials.decrypt(split[1]);
                            Program.authenticators.Add(anAuthenticator);
                        }
                    }
                    catch (IOException e)
                    {
                        Console.WriteLine("The file could not be read:");
                        Console.WriteLine(e.Message);
                    }
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Couldn't find an authenticator file. If this is your first time running this, no worries.");
                Console.WriteLine("If you were expecting to load your authenticators, check to see if the file basicTOTPs.db is located in the same directory this program is running from.");
            }

            Boolean donezo = false;
            while (!donezo)
            {
                Console.WriteLine("Possible commands: add, list, help, exit");
                String command = Console.ReadLine();
                command = command.Trim();
                switch (command)
                {
                    case "add":
                        Authenticator authToAdd = new Authenticator();
                        Console.WriteLine("Cool beans. Give me a name for the account/service you are going to add:");
                        authToAdd.description = Console.ReadLine();
                        Console.WriteLine("Okay, gimme the secret.");
                        String secretToAdd = Console.ReadLine();
                        secretToAdd = Regex.Replace(secretToAdd, @"\s", "");
                        authToAdd.secret = secretToAdd;
                        authenticators.Add(authToAdd);
                        using (StreamWriter sw = new StreamWriter("basicTOTPs.db", true))
                        {
                            sw.Write(Credentials.encrypt(authToAdd.description)+DELIMITER);
                            sw.WriteLine(Credentials.encrypt(authToAdd.secret));
                        }
                        Console.WriteLine("Great! You probably should hit list now to get a value to confirm your code with your service.");
                        break;
                    case "list":
                        foreach (Authenticator auth in authenticators)
                        {
                            Totp atotp = new Totp(Base32Encoding.ToBytes(auth.secret));
                            String value = atotp.ComputeTotp();
                            Console.WriteLine(auth.description + ": " + value);
                        }
                        break;
                    case "help":
                        Console.WriteLine("add - use this to add an authenticator. authenticators are saved to basicTOTPs.db, encrypted using a key saved in your Credential Manager. Right now only supports the default TOTP implementation (SHA-1, 6 digits)");
                        Console.WriteLine("list - use this to generate values for all your authenticators. authenticators used are from basicTOTP, decrypted using a key saved in your Credential Manager. No time is listed for the time remaining for code validity.");
                        Console.WriteLine("help - you are here!");
                        Console.WriteLine("exit - gracefully depart from this application. kudos to you!");
                        break;
                    case "exit":
                        Console.WriteLine("See ya!");
                        donezo = true;
                        break;
                    default:
                        Console.WriteLine("Sorry, I don't understand that command :(");
                        break;
                }
            }
        }
    }
}
