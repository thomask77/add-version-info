# Calculate and manipulate CRC32 checksums
#
#   http://en.wikipedia.org/wiki/Cyclic_redundancy_check
#   http://blog.stalkr.net/2011/03/crc-32-forging.html
#   http://www.woodmann.com/fravia/crctut1.htm
#   http://www.ross.net/crc/crcpaper.html
#
# Copyright (c)2013 StalkR <github-misc@stalkr.net>
# Copyright (c)2018 Thomas Kindler <mail_git@t-kindler.de>
#
# 2015-08-19, tk:   Use bytearrays instead of strings. Fixed indentation and comments.
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

class CRC32(object):
    def __init__(self, poly = 0xedb88320):
        self.table   = [0] * 256
        self.reverse = [0] * 256

        for i in range(256):
            fwd = i
            rev = i << 24

            for _ in range(8, 0, -1):
                # Build normal table
                #
                if fwd & 1:
                    fwd = (fwd >> 1) ^ poly
                else:
                    fwd = fwd >> 1

                self.table[i] = fwd

                # Build reverse table
                #
                if rev & 0x80000000:
                    rev = (((rev ^ poly) << 1) & 0xffffffff) | 1
                else:
                    rev = (rev << 1) & 0xffffffff

                self.reverse[i] = rev
      
       
    def calc(self, crc, data):
        for c in data:
            crc = (crc >> 8) ^ self.table[(crc & 0xff) ^ c]
        return crc


    def calc_back(self, crc, data):
        for c in data[::-1]:
            crc = ((crc << 8) & 0xffffffff) ^ self.reverse[crc >> 24] ^ c
        return crc;

    
    def forge(self, wanted_crc, data, pos):       
        """Forge a checksum that can be written at pos, so that a CRC32 over data yields wanted_crc"""

        # Forward calculation of CRC up to pos, sets current forward CRC state
        #
        fwd_crc = self.calc( 0xffffffff, data[:pos] )

        # Backward calculation of CRC down to pos+4, sets wanted backward CRC state
        #
        bkd_crc = wanted_crc ^ 0xffffffff
        bkd_crc = self.calc_back( bkd_crc, data[pos+4:] )

        # Deduce the 4 bytes we need to insert
        #
        bkd_crc = self.calc_back( bkd_crc, bytearray(struct.pack('<L', fwd_crc)) )

        # Test result
        #
        # test = data[:pos] + struct.pack('<L', bkd_crc) + data[pos+4:]
        # assert( self.calc(0xffffffff, test) ^ 0xffffffff == wanted_crc ), "CRC self test failed"

        return bkd_crc
