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
        private static bool FindSignatureOffset(byte[] signature, byte[] buffer, int start, int len, out int offset)
        {
            bool found = false;
            offset = 0;

            if (start + len >= buffer.Length)
                return false;

            for (int x = start; x < start + len; x++)
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

        private static byte[] CreateJMP(int sourceAddress, int targetAddress)
        {
            int offset = targetAddress - sourceAddress - 5;
            byte[] JMP = new byte[5];
            JMP[0] = 0xE9;
            JMP[1] = (byte)(offset);
            JMP[2] = (byte)(offset >> 8);
            JMP[3] = (byte)(offset >> 16);
            JMP[4] = (byte)(offset >> 24);
            return JMP;
        }

        //Searches for call to Kernel32.Sleep and returns the instruction bytes, returns null on error
        //client 5.0.8.3:  004018CB  |.  FF15 2CB25700  CALL DWORD PTR DS:[<&KERNEL32.Sleep>]
        private static byte[] GetSleepBytes(byte[] fileBuffer)
        {
            int offset;
            byte[] sig1 = new byte[] { 0x8B, 0x44, 0x24, 0x04, 0x83, 0xF8, 0x14, 0x7F, 0x09 };  //4.x & 5.x clients
            byte[] sig2 = new byte[] { 0x8B, 0x4D, 0xB8, 0x0B, 0x4D, 0xBC, 0x0F, 0x84 }; //6.x clients
            byte[] sleep = new byte[6];

            if (FindSignatureOffset(sig1, fileBuffer, out offset))
            {
                Buffer.BlockCopy(fileBuffer, offset + 0x0B, sleep, 0, 6);
                return sleep;
            }

            if (FindSignatureOffset(sig2, fileBuffer, out offset))
            {
                Buffer.BlockCopy(fileBuffer, offset + 0x0E, sleep, 0, 6);
                return sleep;
            }

            return null;
        }

        //Searches for location of the instruction we want to patch
        //This instruction is located within the function labeled loc_5361B4 in Batlin's document
        private static bool GetInjectionAddress(byte[] fileBuffer, out int offset)
        {
            byte[] sig1 = new byte[] { 0x8B, 0x44, 0x24, 0x48, 0x83, 0xC4, 0x04, 0x03, 0xC2 }; //5.x clients
            byte[] sig2 = new byte[] { 0x83, 0xC4, 0x04, 0x03, 0xC8, 0x89, 0x4C, 0x24, 0x4C }; //4.x clients
            byte[] sig3 = new byte[] { 0x83, 0xC4, 0x04, 0x01, 0x44, 0x24, 0x44 }; //6.x clients
            offset = 0;

            if (FindSignatureOffset(sig1, fileBuffer, out offset))
            {
                offset += 0x12;
                return true;
            }

            if (FindSignatureOffset(sig2, fileBuffer, out offset))
            {
                offset += 0x0E;
                return true;
            }

            if (FindSignatureOffset(sig3, fileBuffer, out offset))
            {
                offset += 0x0C;
                return true;
            }

            return false;
        }


        //Credit for this technique goes to Batlin, document describing it can be found here:
        //http://www.joinuo.com/forums/viewtopic.php?f=28&t=175
        private static bool SleepPatch(byte[] fileBuffer)
        {
            byte[] caveSig = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
            int peOffset = BitConverter.ToUInt16(fileBuffer, 0x3C);
            //int baseAddress = BitConverter.ToInt32(fileBuffer, peOffset + 0x18 + 0x1C);
            //int numSections = BitConverter.ToUInt16(fileBuffer, offset + 0x04 + 0x02);
            int firstSectionHeader = peOffset + 0x18 + 0x60 + 0x80;
            int firstSectionVA = BitConverter.ToInt32(fileBuffer, firstSectionHeader + 0x0C);
            int firstSectionLen = BitConverter.ToInt32(fileBuffer, firstSectionHeader + 0x10);
            int caveOffset = 0;

            //search for code cave within first data section (.text)
            if (FindSignatureOffset(caveSig, fileBuffer, firstSectionVA, firstSectionLen, out caveOffset))
            {
                byte[] sleep = GetSleepBytes(fileBuffer);
                if (sleep != null)
                {
                    int iOffset = 0;
                    if (GetInjectionAddress(fileBuffer, out iOffset))
                    {
                        //we need to get the jump destination for the bytes we're overwriting and restore the jump later
                        int origJump = BitConverter.ToInt32(fileBuffer, iOffset + 1) + 5;
                        origJump += iOffset;
                        //here we assemble the JMP instruction from our code cave to the original destination
                        byte[] newJump = CreateJMP(caveOffset + 8, origJump);
                        byte[] jumpToCave = CreateJMP(iOffset, caveOffset);
                        //patch in the jump to our cave
                        Buffer.BlockCopy(jumpToCave, 0, fileBuffer, iOffset, 5);
                        //now we assemble our instructions for the cave
                        //push 1:
                        fileBuffer[caveOffset] = 0x6A;
                        fileBuffer[caveOffset + 1] = 0x01;
                        //call sleep:
                        Buffer.BlockCopy(sleep, 0, fileBuffer, caveOffset + 2, 6);
                        //restore the code we stole earlier:
                        Buffer.BlockCopy(newJump, 0, fileBuffer, caveOffset + 8, 5);
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("Signature for Batlin's loc_5361B4 function not found!");
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("Signature for Kernel32.Sleep not found!");
                    return false;
                }
            }
            else
            {
                Console.WriteLine("No suitable code cave found for Batlin's sleep patch!");
            }
            return false;
        }
    }
}