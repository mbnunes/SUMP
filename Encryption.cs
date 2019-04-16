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

namespace SUMP
{
    partial class Program
    {

        private static bool DecryptPatch(byte[] fileBuffer)
        {
            byte[] oldClientSig = new byte[] { 0x8B, 0x86, 0x04, 0x01, 0x0A, 0x00, 0x85, 0xC0, 0x74, 0x52 };
            byte[] oldClientPatched = new byte[] { 0x8B, 0x86, 0x04, 0x01, 0x0A, 0x00, 0x3B, 0xC0, 0x74, 0x52 };
            byte[] newClientSig = new byte[] { 0x74, 0x37, 0x83, 0xBE, 0xB4, 0x00, 0x00, 0x00, 0x00 };
            byte[] newClientPatched = new byte[] { 0xEB, 0x37, 0x83, 0xBE, 0xB4, 0x00, 0x00, 0x00, 0x00 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset + 0x06] = 0x3B;
                Console.WriteLine("Packet decryption removed!");
                return true;
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset] = 0xEB;
                Console.WriteLine("Packet decryption removed!");
                return true;
            }

            if (FindSignatureOffset(oldClientPatched, fileBuffer, out offset))
            {
                Console.WriteLine("Signature found for packet decryption, but patch is already applied!");
                return true;
            }

            if (FindSignatureOffset(newClientPatched, fileBuffer, out offset))
            {
                Console.WriteLine("Signature found for packet decryption, but patch is already applied!");
                return true;
            }
            return false;
        }

        private static bool TwoFishCryptPatch(byte[] fileBuffer)
        {
            byte[] oldClientSig = new byte[] { 0x8B, 0xD9, 0x8B, 0xC8, 0x48, 0x85, 0xC9, 0x0F, 0x84 };
            byte[] newClientSig = new byte[] { 0x74, 0x0F, 0x83, 0xB9, 0xB4, 0x00, 0x00, 0x00, 0x00 };
            byte[] newClientPatched = new byte[] { 0xEB, 0x0F, 0x83, 0xB9, 0xB4, 0x00, 0x00, 0x00, 0x00 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset + 0x08] = 0x85;
                Console.WriteLine("Twofish encryption removed!");
                return true;
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset] = 0xEB;
                Console.WriteLine("Twofish encryption removed!");
                return true;
            }

            if (FindSignatureOffset(newClientPatched, fileBuffer, out offset))
            {
                Console.WriteLine("Signature found for twofish encryption, but patch is already applied!");
                return true;
            }
            return false;
        }

        private static bool LoginCryptPatch(byte[] fileBuffer)
        {
            byte[] oldClientSig = new byte[] { 0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8F };
            byte[] newClientSig = new byte[] { 0x75, 0x12, 0x8B, 0x54, 0x24, 0x0C };
            byte[] newClientPatched = new byte[] { 0xEB, 0x12, 0x8B, 0x54, 0x24, 0x0C };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset + 0x15] = 0x84;
                Console.WriteLine("Login encryption removed!");
                return true;
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset] = 0xEB;
                Console.WriteLine("Login encryption removed!");
                return true;
            }

            if (FindSignatureOffset(newClientPatched, fileBuffer, out offset))
            {
                Console.WriteLine("Signature found for login encryption, but patch is already applied!");
                return true;
            }
            return false;
        }

        /* Thanks to Daniel 'Necr0Potenc3' Cavalcanti for the encryption removal information.
           He may or may not have ripped it from Injection, never checked */
        private static bool PatchEncryption(byte[] fileBuffer)
        {
            if (!LoginCryptPatch(fileBuffer))
            {
                Console.WriteLine("Signature for login encryption not found, aborting...");
                return false;
            }
            if (!TwoFishCryptPatch(fileBuffer))
            {
                Console.WriteLine("Signature for twofish encryption not found, aborting...");
                return false;
            }
            if (!DecryptPatch(fileBuffer))
            {
                Console.WriteLine("Signature for packet decryption not found, aborting...");
                return false;
            }
            return true;
        }
    }
}