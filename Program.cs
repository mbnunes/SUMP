/* Copyright (C) 2012 Matthew Geyer
 * 
 * This file is part of SUMP.
 * 
 * SUMP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SUMP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SUMP.  If not, see <http://www.gnu.org/licenses/>. */


using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace SUMP
{
    partial class Program
    {
        [Flags]
        private enum Options : byte
        {
            None = 0x00,
            Multi = 0x01 << 0,
            Stamina = 0x01 << 1,
            Light = 0x01 << 2,
            Batlin = 0x01 << 3,
            NoDraw = 0x01 << 4,
            Encrypt = 0x01 << 6,
            Hifi = 0x01 << 7,
        }

        private static bool FindSignatureOffset(byte[] signature, byte[] buffer, out int offset)
        {
            bool found = false;
            offset = 0;
            for (int x = 0; x < buffer.Length - signature.Length; x++)
            {
                for (int y = 0; y < signature.Length; y++)
                {
                    if (buffer[x + y] == signature[y])
                        found = true;
                    else
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    offset = x;
                    break;
                }
            }
            return found;
        }

        private static void PrintException(Exception x)
        {
            while (x.InnerException != null)
                x = x.InnerException;
            StringBuilder sb = new StringBuilder();
            sb.Append(x.Message);
            sb.Append("\r\n");
            sb.Append(x.StackTrace);
            Console.WriteLine(sb.ToString());
            try
            {
                File.WriteAllText("SUMP.LOG", sb.ToString(), Encoding.UTF8);
                Console.WriteLine("Exception logged to: SUMP.LOG");
            }
            catch { }
        }

        private static void Save(string filename, byte[] fileBuffer)
        {
            string newFilename = Path.GetFileNameWithoutExtension(filename) + "_patched.exe";
            try
            {
                File.WriteAllBytes(newFilename, fileBuffer);
            }
            catch (Exception ex)
            {
                PrintException(ex);
                return;
            }
            Console.WriteLine(string.Format("Patch successful, file saved as \"{0}\".", newFilename));
        }

        private static void Patch(string filename, Options o)
        {
            if (o == Options.None)
            {
                Console.WriteLine("No patches selected, aborting...");
                return;
            }

            if (File.Exists(filename))
            {
                byte[] buffer = File.ReadAllBytes(filename);
                if ((o & Options.Multi) == Options.Multi)
                {
                    if (MultiPatch(buffer))
                    {
                        Console.WriteLine("Multi-UO patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Multi-UO patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.Stamina) == Options.Stamina)
                {
                    if (StaminaPatch(buffer))
                    {
                        Console.WriteLine("Stamina patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Stamina patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.Light) == Options.Light)
                {
                    if (LightPatch(buffer))
                    {
                        Console.WriteLine("Always light patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Always light patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.Batlin) == Options.Batlin)
                {
                    if (SleepPatch(buffer))
                    {
                        Console.WriteLine("Batlin's sleep patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Batlin's sleep patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.NoDraw) == Options.NoDraw)
                {
                    if (NoDrawPatch(buffer))
                    {
                        Console.WriteLine("Garret's no-draw patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Garret's no-draw patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.Encrypt) == Options.Encrypt)
                {
                    if (PatchEncryption(buffer))
                    {
                        Console.WriteLine("Encryption removal patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Encryption removal patch is unsuccessful, aborting...");
                        return;
                    }
                }

                if ((o & Options.Hifi) == Options.Hifi)
                {
                    if (SoundPatch(buffer))
                    {
                        Console.WriteLine("Hifi's global sound patch is successful.");
                    }
                    else
                    {
                        Console.WriteLine("Hifi's global sound patch is unsuccessful, aborting...");
                        return;
                    }
                }

                Save(filename, buffer);
            }
            else
            {
                Console.WriteLine(string.Format("File \"{0}\" not found!", filename));
            }
        }

        static void Main(string[] args)
        {
            Options o = Options.None;

            Console.WriteLine("Simple Ultima Multi Patcher .4");
            Console.WriteLine("Currently supported UO clients: 4.x - 7.x");

            if (args.Length == 0)
            {
                Console.WriteLine("Note: wildcards are supported for filename.  For example: *.exe\r\n");
                Console.WriteLine("Usage: SUMP.exe <filename> <options>");
                Console.WriteLine("Example: SUMP.exe client.exe -m -l -s -b -g -e -h");
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("-m : Apply multi-uo patch which allows you to run multiple clients.");
                Console.WriteLine("-l : Apply always light patch.");
                Console.WriteLine("-s : Remove stamina check when pushing through mobiles.");
                Console.WriteLine("-b : Apply Batlin's sleep patch to reduce CPU usage.");
                Console.WriteLine("-g : Apply Garret's patch to display no-draw items.");
                Console.WriteLine("-e : Remove protocol encryption (and decryption).");
                Console.WriteLine("-h : Apply hifi's global sound patch which enables sound for minimized client.");
                return;
            }

            for (int x = 1; x < args.Length; x++)
            {
                switch (args[x].ToLower())
                {
                    case "-m":
                        o |= Options.Multi;
                        break;
                    case "-l":
                        o |= Options.Light;
                        break;
                    case "-s":
                        o |= Options.Stamina;
                        break;
                    case "-b":
                        o |= Options.Batlin;
                        break;
                    case "-g":
                        o |= Options.NoDraw;
                        break;
                    case "-e":
                        o |= Options.Encrypt;
                        break;
                    case "-h":
                        o |= Options.Hifi;
                        break;
                }
            }


            try
            {
                string searchPath = Path.GetDirectoryName(args[0]);
                if (string.IsNullOrEmpty(searchPath))
                    searchPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string searchPattern = Path.GetFileName(args[0]);
                foreach (string s in Directory.GetFiles(searchPath, searchPattern, SearchOption.TopDirectoryOnly))
                {
                    Console.WriteLine(String.Format("Attempting to patch \"{0}\"...\r\n", s));
                    Patch(s, o);
                }
            }
            catch (Exception ex)
            {
                PrintException(ex);
            }

        }
    }
}
