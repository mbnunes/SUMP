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
        private static bool ErrorCheckPatch(byte[] fileBuffer)
        {
            /* Patches the following check:
             * GetLastError returns non-zero */

            byte[] oldClientSig = new byte[] { 0x85, 0xC0, 0x75, 0x2F, 0xBF };
            byte[] newClientSig = new byte[] { 0x85, 0xC0, 0x5F, 0x5E, 0x75, 0x2F };
            byte[] oldPatched = new byte[] { 0x66, 0x33, 0xC0, 0x90, 0xBF };
            byte[] newPatched = new byte[] { 0x85, 0xC0, 0x5F, 0x5E, 0x90, 0x90 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset)) //signature = target bytes, so no check necessary
            {
                //XOR AX, AX
                fileBuffer[offset] = 0x66;
                fileBuffer[offset + 1] = 0x33;
                fileBuffer[offset + 2] = 0xC0;
                fileBuffer[offset + 3] = 0x90;
                return true;
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset)) //signature = target bytes, so no check necessary
            {
                fileBuffer[offset + 4] = 0x90;
                fileBuffer[offset + 5] = 0x90;
                return true;
            }

            if (FindSignatureOffset(oldPatched, fileBuffer, out offset) || FindSignatureOffset(newPatched, fileBuffer, out offset))
            {
                Console.WriteLine("Signature found (multi-uo patch #3), but patch is already applied!");
                return true;
            }
            return false;
        }

        private static bool SingleCheckPatch(byte[] fileBuffer)
        {
            /* Patches the following check:
             * "Another copy of UO is already running!" */

            byte[] oldClientSig = new byte[] { 0xC7, 0x44, 0x24, 0x10, 0x11, 0x01, 0x00, 0x00 };
            byte[] newClientSig = new byte[] { 0x83, 0xC4, 0x04, 0x33, 0xDB, 0x53, 0x50 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x17] == 0x74)
                {
                    fileBuffer[offset + 0x17] = 0xEB;
                    return true;
                }
                else if (fileBuffer[offset + 0x17] == 0xEB)
                {
                    Console.WriteLine("Signature found (multi-uo patch #1), but patch is already applied!");
                    return true;
                }
                else
                {
                    Console.WriteLine("Signature found (multi-uo patch #1), but actual byte differs from expected.  Aborting...");
                    return false;
                }
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x0F] == 0x74)
                {
                    fileBuffer[offset + 0x0F] = 0xEB;
                    return true;
                }
                else if (fileBuffer[offset + 0x0F] == 0xEB)
                {
                    Console.WriteLine("Signature found (multi-uo patch #1), but patch is already applied!");
                    return true;
                }
                else
                {
                    Console.WriteLine("Signature found (multi-uo patch #1), but actual byte differs from expected.  Aborting...");
                    return false;
                }
            }

            return false;
        }

        private static bool TripleCheckPatch(byte[] fileBuffer)
        {
            /* Patches following checks:
             * "Another instance of UO may already be running."
             * "Another instance of UO is already running."
             * "An instance of UO Patch is already running." */

            byte[] oldClientSig = new byte[] { 0xFF, 0xD6, 0x6A, 0x01, 0xFF, 0xD7, 0x68 };
            byte[] newClientSig = new byte[] { 0x3B, 0xC3, 0x89, 0x44, 0x24, 0x08 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                if (fileBuffer[offset - 0x2D] == 0x75 && fileBuffer[offset - 0x0E] == 0x75 && fileBuffer[offset + 0x18] == 0x74)
                {
                    fileBuffer[offset - 0x2D] = 0xEB;
                    fileBuffer[offset - 0x0E] = 0xEB;
                    fileBuffer[offset + 0x18] = 0xEB;
                    return true;
                }
                else if (fileBuffer[offset - 0x2D] == 0xEB && fileBuffer[offset - 0x0E] == 0xEB && fileBuffer[offset + 0x18] == 0xEB)
                {
                    Console.WriteLine("Signature found (multi-uo patch #2), but patch is already applied!");
                    return true;
                }
                else
                {
                    Console.WriteLine("Signature found (multi-uo patch #2), but actual byte differs from expected.  Aborting...");
                    return false;
                }
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x06] == 0x75 && fileBuffer[offset + 0x2D] == 0x75 && fileBuffer[offset + 0x5F] == 0x74)
                {
                    fileBuffer[offset + 0x06] = 0xEB;
                    fileBuffer[offset + 0x2D] = 0xEB;
                    fileBuffer[offset + 0x5F] = 0xEB;
                    return true;
                }
                else if (fileBuffer[offset + 0x06] == 0xEB && fileBuffer[offset + 0x2D] == 0xEB && fileBuffer[offset + 0x5F] == 0xEB)
                {
                    Console.WriteLine("Signature found (multi-uo patch #2), but patch is already applied!");
                    return true;
                }
                else
                {
                    Console.WriteLine("Signature found (multi-uo patch #2), but actual byte differs from expected.  Aborting...");
                    return false;
                }
            }

            return false;
        }

        private static bool NewStyleMulti(byte[] fileBuffer)
        {
            byte[] sig = new byte[] { 0x83, 0xC4, 0x04, 0x33, 0xED, 0x55, 0x50 };
            int offset;

            if (FindSignatureOffset(sig, fileBuffer, out offset))
            {
                if (fileBuffer[offset + 0x15] == 0x74)
                {
                    fileBuffer[offset + 0x15] = 0xEB;
                    return true;
                }
                if (fileBuffer[offset + 0x15] == 0xEB)
                {
                    Console.WriteLine("Signature found (new style multi-uo patch), but patch is already applied!");
                    return true;
                }
            }
            return false;
        }

        private static bool MultiPatch(byte[] buffer)
        {
            if (!NewStyleMulti(buffer))
            {
                if (!SingleCheckPatch(buffer) || !TripleCheckPatch(buffer) || !ErrorCheckPatch(buffer))
                {
                    return false;
                }
            }
            return true;
        }
    }
}