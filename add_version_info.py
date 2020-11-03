#!/usr/bin/env python3
#
# Add CRC checksum and version information to ELF and binary files
#
# Copyright (c)2015-2018 Thomas Kindler <mail_git@t-kindler.de>
#
# 2018-07-28, tk:   v3.0.0, Ported to Python 3
# 2016-01-09, tk:   v2.1.0, --stm32 option for STM32 hardware compatible CRCs
# 2015-08-19, tk:   v2.0.2, Improved performance. Added --no-crc option
# 2015-07-04, tk:   v2.0.1, Don't load data for SHT_NOBITS sections
# 2015-06-20, tk:   v2.0.0, Support for ELF64 and binary files, elf_reader
#                           rewritten from scratch. New options for version
#                           control command and desired CRC
# 2015-02-14, tk:   v1.1.0, Added SVN support
# 2015-01-24, tk:   v1.0.0, Initial implementation
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import argparse
import subprocess
import getpass
import platform
import ctypes
import datetime
import os
import struct

import elf_reader
from crc32_forge import CRC32


ENCODING = "iso8859-15"

VCS_INFO_START = b"VCSINFO2_START->"
VCS_INFO_END   = b"<---VCSINFO2_END"


class version_info(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("vcs_info_start", ctypes.c_char * 16),

        # set by add-version-info.py
        #
        ("image_crc"    , ctypes.c_uint32),
        ("image_start"  , ctypes.c_uint32),
        ("image_size"   , ctypes.c_uint32),
        ("vcs_id"       , ctypes.c_char * 32),
        ("build_user"   , ctypes.c_char * 16),
        ("build_host"   , ctypes.c_char * 16),
        ("build_date"   , ctypes.c_char * 16),
        ("build_time"   , ctypes.c_char * 16),
        ("product_name" , ctypes.c_char * 32),
        ("major"        , ctypes.c_int32),
        ("minor"        , ctypes.c_int32),
        ("patch"        , ctypes.c_int32),

        ("vcs_info_end" , ctypes.c_char * 16)
    ]


def dprint(*text):
    if args.verbose:
        for s in text:
            print(s, end=' ')
        print()


def fill_version_info(info):
    dprint("Running \"%s\"..." % args.command)

    info.vcs_id = subprocess.check_output(args.command, shell=True).strip()
    dprint(info.vcs_id.decode(ENCODING))

    info.build_user = bytes(getpass.getuser(), ENCODING)
    info.build_host = bytes(platform.node(), ENCODING)

    mtime = datetime.datetime.fromtimestamp( os.path.getmtime(args.source) )
    info.build_date = bytes(mtime.strftime("%Y-%m-%d"), ENCODING)
    info.build_time = bytes(mtime.strftime("%H:%M:%S"), ENCODING)


def parse_args():
    global args

    parser = argparse.ArgumentParser(
        description="Add CRC checksum and version information to an ELF or binary file",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "source", help="source file"
    )

    parser.add_argument(
        "target", nargs="?",
        help="Target file (default: overwrite source)"
    )

    parser.add_argument(
        "--version", action="version", version="%(prog)s 3.0.0"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print status messages"
    )

    parser.add_argument(
        "-c", "--command", default="git describe --always --dirty",
        help="Version control command.\n"
             "Use \"svnversion -n\" for subversion projects.\n"
             "(default: \"%(default)s\")"
    )

    parser.add_argument(
        "-r", "--raw", action="store_true",
        help="Patch binary file instead of ELF"
    )

    parser.add_argument(
        "--crc", default="0x00000000",
        help="Desired CRC result for the image\n"
             "(default: %(default)s)"
    )

    parser.add_argument(
        "--stm32", action="store_true",
        help="Make STM32F4 CRC hardware compatible checksum"
    )

    parser.add_argument(
        "-n", "--no-crc", action="store_true",
        help="Don't calculate CRC checksum"
    )

    parser.add_argument(
        "-f", "--force", action="store_true",
        help="Force update if already filled out"
    )

    args = parser.parse_args()

    args.crc = int(args.crc, 0)

    if args.source.endswith((".bin", ".exe")):
        args.raw = True

    if args.target is None:
        args.target = args.source


def find_info_offset(data):
    data = bytearray(data)

    offset = 0
    while True:
        offset = data.find(VCS_INFO_START, offset)
        if offset < 0:
            return -1

        if data[offset + ctypes.sizeof(version_info) - 16:
                offset + ctypes.sizeof(version_info) ] == VCS_INFO_END:
            return offset

        offset += len(VCS_INFO_START)


def bitrev32(x):
    x = ((x & 0x55555555) <<  1) | ((x & 0xAAAAAAAA) >>  1)
    x = ((x & 0x33333333) <<  2) | ((x & 0xCCCCCCCC) >>  2)
    x = ((x & 0x0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0) >>  4)
    x = ((x & 0x00FF00FF) <<  8) | ((x & 0xFF00FF00) >>  8)
    x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16)
    return x


def stm32_shuffle(data):
    out = bytearray()
    for i in range(0, len(data), 4):
        out += struct.pack('<L', bitrev32(struct.unpack_from('<L', data, i)[0]))
    return out


def stm32_hw_crc(data):
    crc = 0xffffffff
    for i in range(0, len(data), 4):
        crc = crc ^ struct.unpack_from('<L', data, i)[0]
        for _ in range(32):
            if crc & 0x80000000:
                crc = ((crc << 1) & 0xffffffff) ^ 0x04C11DB7;
            else:
                crc = (crc << 1) & 0xffffffff
    return crc


def forge_crc(data, offset):
    if args.no_crc:
        return 0
    elif args.stm32:
        return bitrev32(CRC32().forge(bitrev32(args.crc ^ 0xffffffff), stm32_shuffle(data), offset))
    else:
        return CRC32().forge(args.crc, data, offset)


def patch_raw(data):
    dprint("Searching for structure marker...")

    info_offset = find_info_offset(data)
    if info_offset < 0:
        raise Exception("structure marker not found")

    dprint("  found at %d" % info_offset)

    info = version_info.from_buffer(data, info_offset)

    if info.image_crc and not args.force:
        raise Exception("already filled out")

    fill_version_info(info)

    info.image_start = 0
    info.image_size = len(data)
    info.image_crc = forge_crc(data, info_offset + version_info.image_crc.offset)

    dprint("  image_crc   = 0x%08x" % info.image_crc)
    dprint("  image_size  = %d" % info.image_size)


def patch_elf(data):
    elf = elf_reader.ELFObject.from_bytes(data)
    for s in elf.sections:
        dprint("  %-16s: 0x%08x -> 0x%08x %8d" % (s.name.decode(ENCODING), s.lma, s.sh_addr, s.sh_size))

    dprint("Searching for structure marker...")

    for info_section in elf.sections:
        info_offset = find_info_offset(info_section.data)
        if info_offset >= 0:
            break
    else:
        raise Exception("structure marker not found")

    dprint("  found in %s at %d" % (info_section.name.decode(ENCODING), info_offset))

    info = version_info.from_buffer(info_section.data, info_offset)

    if info.image_crc and not args.force:
        raise Exception("already filled out")

    fill_version_info(info)

    info.image_start = elf.sections[0].lma
    info.image_size = elf.sections[-1].lma + elf.sections[-1].sh_size - elf.sections[0].lma
    info.image_crc = forge_crc( elf.to_bin(),
        info_section.lma - elf.sections[0].lma + info_offset + version_info.image_crc.offset
    )

    dprint("  image_crc   = 0x%08x" % info.image_crc)
    dprint("  image_start = 0x%08x" % info.image_start)
    dprint("  image_size  = %d" % info.image_size)


if __name__ == '__main__':
    parse_args()

    dprint("Loading \"%s\"..." % args.source)

    with open(args.source, "rb") as f:
        data = bytearray(f.read())

    if args.raw:
        patch_raw(data)
    else:
        patch_elf(data)

    dprint("Saving \"%s\"..." % args.target)

    with open(args.target, "wb") as f:
        f.write(data)
