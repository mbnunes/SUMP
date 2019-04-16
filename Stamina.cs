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
        private static bool StaminaPatch(byte[] fileBuffer)
        {
            //byte[] oldClientSig = new byte[] { 0x8B, 0x91, 0x10, 0x02, 0x00, 0x00, 0x8B, 0x81 };
            byte[] oldClientSig = new byte[] { 0x0F, 0xBF, 0x47, 0x26, 0x39, 0x44, 0x24, 0x28, 0x75 };
            byte[] newClientSig = new byte[] { 0x8B, 0x91, 0x1C, 0x02, 0x00, 0x00, 0x3B, 0x91 };
            int offset;

            if (FindSignatureOffset(oldClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset + 0x28] = 0xC0;
                return true;
            }

            if (FindSignatureOffset(newClientSig, fileBuffer, out offset))
            {
                fileBuffer[offset + 0x0C] = 0xEB;
                return true;
            }
            return false;
        }
    }
}