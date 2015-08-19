# Calculate and manipulate CRC32
#
#   http://en.wikipedia.org/wiki/Cyclic_redundancy_check
#   http://blog.stalkr.net/2011/03/crc-32-forging.html
#   http://www.woodmann.com/fravia/crctut1.htm
#
# Copyright (c)2013 StalkR <github-misc@stalkr.net>
# Copyright (c)2015 Thomas Kindler <mail_git@t-kindler.de> 
#
# 2015-08-19, tk:   Use bytearray instead of string. Fixed indentation and comments.
# 2015-01-29, tk:   Changed forge() to skip the bytes at pos instead of inserting
#                   them there. Also return the forged CRC instead of changed data.
# 2015-01-28, tk:   Taken from github, added copyright header. See
#                   https://github.com/StalkR/misc/blob/master/crypto/crc32.py
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import struct


# Polynoms in reversed notation
#
POLYNOMS = {
    'CRC-32-IEEE':  0xedb88320,     # 802.3
    'CRC-32C':      0x82F63B78,     # Castagnoli
    'CRC-32K':      0xEB31D82E,     # Koopman
    'CRC-32Q':      0xD5828281,
}


class Error(Exception):
    pass


class CRC32(object):
    """A class to calculate and manipulate CRC32.

    Use one instance per type of polynom you want to use.
    Use calc() to calculate a crc32.
    Use forge() to forge crc32 by adding 4 bytes anywhere.
    """
    def __init__(self, type="CRC-32-IEEE"):
        if type not in POLYNOMS:
            raise Error("Unknown polynom %s." % type)

        self.polynom = POLYNOMS[type]
        self._build_tables()

    def _build_tables(self):
        self.table = [0]*256
        self.reverse = [0]*256
        for i in range(256):
            fwd = i
            rev = i << 24
            for j in range(8, 0, -1):
                # Build normal table
                #
                if (fwd & 1) == 1:
                    fwd = (fwd >> 1) ^ self.polynom
                else:
                    fwd >>= 1
                self.table[i] = fwd & 0xffffffff

                # Build reverse table =)
                #
                if rev & 0x80000000 == 0x80000000:
                    rev = ((rev ^ self.polynom) << 1) | 1
                else:
                    rev <<= 1
                self.reverse[i] = rev & 0xffffffff

    def calc(self, data):
        """Calculate crc32 of a bytearray. Same crc32 as in (binascii.crc32)&0xffffffff."""
        crc = 0xffffffff
        for c in data:
            crc = (crc >> 8) ^ self.table[(crc ^ c) & 0xff]
        return crc ^ 0xffffffff

    def forge(self, wanted_crc, data, pos):
        """Forge a checksum that can be written at pos, so that a CRC32 over s yields the wanted_crc."""

        # Forward calculation of CRC up to pos, sets current forward CRC state
        #
        fwd_crc = 0xffffffff
        for c in data[:pos]:
            fwd_crc = (fwd_crc >> 8) ^ self.table[(fwd_crc ^ c) & 0xff]

        # Backward calculation of CRC down to pos+4, sets wanted backward CRC state
        #
        bkd_crc = wanted_crc ^ 0xffffffff
        for c in data[pos+4:][::-1]:
            bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ self.reverse[bkd_crc >> 24] ^ c

        # Deduce the 4 bytes we need to insert
        #
        for c in bytearray(struct.pack('<L', fwd_crc)[::-1]):
            bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ self.reverse[bkd_crc >> 24] ^ c

        # Test result
        #
        # assert(self.calc(data[:pos] + struct.pack('<L', bkd_crc) + data[pos+4:]) == wanted_crc)

        return bkd_crc
