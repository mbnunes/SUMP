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
        /* Credit to hifi for the patch information, I added support for more clients:
         * http://hifi.iki.fi/uo-gsound.c */
        private static bool SoundPatch(byte[] fileBuffer)
        {
            byte[] sig1 = new byte[] { 0xC7, 0x44, 0x24, 0x3C, 0xE0, 0x00, 0x01, 0x00 };
            byte[] sig1Patched = new byte[] { 0xC7, 0x44, 0x24, 0x3C, 0xE0, 0x80, 0x01, 0x00 };
            byte[] sig2 = new byte[] { 0xC7, 0x44, 0x24, 0x28, 0xE0, 0x00, 0x01, 0x00 };
            byte[] sig2Patched = new byte[] { 0xC7, 0x44, 0x24, 0x28, 0xE0, 0x80, 0x01, 0x00 };
            int offset;

            if (FindSignatureOffset(sig1, fileBuffer, out offset))
            {
                fileBuffer[offset + 5] = 0x80;
                return true;
            }

            if (FindSignatureOffset(sig2, fileBuffer, out offset))
            {
                fileBuffer[offset + 5] = 0x80;
                return true;
            }

            if (FindSignatureOffset(sig1Patched, fileBuffer, out offset))
            {
                Console.WriteLine("Hifi's global sound patch is already applied!");
                return true;
            }

            if (FindSignatureOffset(sig2Patched, fileBuffer, out offset))
            {
                Console.WriteLine("Hifi's global sound patch is already applied!");
                return true;
            }
            return false;
        }
    }
}