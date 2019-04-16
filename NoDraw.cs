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
        /* Credit to Garret for the patch information:
         * http://www.joinuo.com/forums/viewtopic.php?f=28&t=504 */
        private static bool NoDrawPatch(byte[] fileBuffer)
        {
            byte[] sig1 = new byte[] { 0x3D, 0xA4, 0x21 };
            byte[] sig2 = new byte[] { 0x3D, 0x98, 0x21 };
            byte[] sig3 = new byte[] { 0x3D, 0xBC, 0x21 };
            byte[] sig4 = new byte[] { 0x81, 0xFB, 0xA4, 0x21 };
            byte[] sig5 = new byte[] { 0x81, 0xFB, 0x98, 0x21 };
            byte[] sig6 = new byte[] { 0x81, 0xFB, 0xBC, 0x21 };

            bool s1 = false, s2 = false, s3 = false, s4 = false, s5 = false, s6 = false;

            int offset;

            while (FindSignatureOffset(sig1, fileBuffer, out offset))
            {
                fileBuffer[offset + 1] = 0;
                fileBuffer[offset + 2] = 0;
                s1 = true;
            }

            while (FindSignatureOffset(sig2, fileBuffer, out offset))
            {
                fileBuffer[offset + 1] = 0;
                fileBuffer[offset + 2] = 0;
                s2 = true;
            }

            while (FindSignatureOffset(sig3, fileBuffer, out offset))
            {
                fileBuffer[offset + 1] = 0;
                fileBuffer[offset + 2] = 0;
                s3 = true;
            }

            while (FindSignatureOffset(sig4, fileBuffer, out offset))
            {
                fileBuffer[offset + 2] = 0;
                fileBuffer[offset + 3] = 0;
                s4 = true;
            }

            while (FindSignatureOffset(sig5, fileBuffer, out offset))
            {
                fileBuffer[offset + 2] = 0;
                fileBuffer[offset + 3] = 0;
                s5 = true;
            }

            while (FindSignatureOffset(sig6, fileBuffer, out offset))
            {
                fileBuffer[offset + 2] = 0;
                fileBuffer[offset + 3] = 0;
                s6 = true;
            }
            if (!(s4 == s5 == s6 == false || s4 == s5 == s6 == true))
                return false;  //only partially patched
            return s1 == s2 == s3 == true;
            /* Just because we return true it doesn't necessarily mean that the entire patch was applied.
             * To figure that out properly we'd need to make a table with info on every client and make
             * this patch much more complex; this is a good compromise.
             * At worst only the display filters will be patched and some or none of the shift-item-handle
             * filters will be patched */
        }
    }
}