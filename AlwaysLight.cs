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
        private static bool LightPatch(byte[] fileBuffer)
        {
            byte[] sig1 = new byte[] { 0x25, 0xFF, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x0C };
            byte[] sig2 = new byte[] { 0x8A, 0x4C, 0x24, 0x0F, 0x0F, 0xB6, 0xC1, 0x83, 0xC4 };
            byte[] sig3 = new byte[] { 0x8B, 0xC1, 0x83, 0xC4, 0x0C, 0x25, 0xFF, 0x00, 0x00, 0x00, 0x3B, 0xD0 };
            int offset;

            if (FindSignatureOffset(sig1, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x0A] == 0x74)
                {
                    fileBuffer[offset + 0x0A] = 0xEB;
                    return true;
                }
                if (fileBuffer[offset + 0x0A] == 0xEB)
                {
                    Console.WriteLine("Signature found (always light), but patch is already applied!");
                    return true;
                }
            }

            if (FindSignatureOffset(sig2, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x10] == 0x74)
                {
                    fileBuffer[offset + 0x10] = 0xEB;
                    return true;
                }
                if (fileBuffer[offset + 0x10] == 0xEB)
                {
                    Console.WriteLine("Signature found (always light), but patch is already applied!");
                    return true;
                }
            }

            if (FindSignatureOffset(sig3, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x0C] == 0x74)
                {
                    fileBuffer[offset + 0x0C] = 0xEB;
                    return true;
                }
                if (fileBuffer[offset + 0x0C] == 0xEB)
                {
                    Console.WriteLine("Signature found (always light), but patch is already applied!");
                    return true;
                }
            }

            return false;
        }
    }
}