#!/usr/bin/env python2
#
# Add CRC checksum and version information to ELF and binary files
#
# Copyright (c)2015 Thomas Kindler <mail_git@t-kindler.de>
#     
# 2015-07-04, tk:  v2.0.1, Don't load data for SHT_NOBITS sections.
#
# 2015-06-20, tk:  v2.0.0, Support for ELF64 and binary files,
#                  elf_reader rewritten from scratch. New options
#                  for version control command and desired CRC.  
#
# 2015-02-14, tk:  v1.1.0, Added svn support.
#
# 2015-01-24, tk:  v1.0.0, Initial implementation.
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
import sys
import argparse
import subprocess
import getpass
import platform
import elf_reader

from ctypes import *
from datetime import datetime
from crc32_forge import CRC32


VCS_INFO_START = "VCSINFO2_START->"
VCS_INFO_END   = "<---VCSINFO2_END"


class version_info(Structure):
    _fields_ = [
        ("vcs_info_start", c_char * 16),

        # set by add-version-info.py
        #
        ("image_crc"    , c_uint32),        # see offsetof_image_crc
        ("image_start"  , c_uint32),
        ("image_size"   , c_uint32),
        ("vcs_id"       , c_char * 32),
        ("build_user"   , c_char * 16),
        ("build_host"   , c_char * 16),
        ("build_date"   , c_char * 16),
        ("build_time"   , c_char * 16),

        # set at compile-time
        #
        ("product_name" , c_char * 32),
        ("major"        , c_int),
        ("minor"        , c_int),
        ("patch"        , c_int),

        ("vcs_info_end" , c_char * 16)
    ]

    offsetof_image_crc = 16     # workaround for missing ctypes.offsetof :/


def fill_version_info(info):
    dprint("running \"%s\"..." % args.command)
    
    info.vcs_id = subprocess.check_output(args.command, shell=True).strip()
    dprint(info.vcs_id)

    info.build_user = getpass.getuser()
    info.build_host = platform.node()

    now = datetime.now()
    info.build_date = now.strftime("%Y-%m-%d")
    info.build_time = now.strftime("%H:%M:%S")


def dprint(*str):
    if args.verbose:
        for s in str:
            print s,
        print


def print_ctype(c):
    for field_name, field_type in c._fields_:
        print "%s = %s" % (field_name, getattr(c, field_name))


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
        help="target file (default: overwrite source)"
    )
    
    parser.add_argument(
        "--version", action="version", version="%(prog)s 2.0.1"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", 
        help="print status messages"
    )

    parser.add_argument(
        "-c", "--command", default="git describe --always --dirty",
        help="version control command.\n"
             "Use \"svnversion -n\" for subversion projects.\n"
             "(default: \"%(default)s\")"
    )

    parser.add_argument(
        "-r", "--raw", action="store_true",
        help="patch binary file instead of ELF"
    )

    parser.add_argument(
        "--crc", default="0x00000000",
        help="desired CRC result for the image\n"
             "(default: %(default)s)"
    )

    parser.add_argument(
        "-f", "--force", action="store_true", 
        help="force update if already filled out"
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

        if data[offset + sizeof(version_info)-16 :
                offset + sizeof(version_info)] == VCS_INFO_END:
            return offset

        offset += len(VCS_INFO_START)


def patch_raw():
    dprint("loading \"%s\"..." % args.source)

    with open(args.source, "rb") as f:
        raw_data = bytearray(f.read())

    ##########

    dprint("searching for structure marker...")

    info_offset = find_info_offset(raw_data)
    if info_offset < 0:
        raise Exception("structure marker not found")

    dprint("  found at %d" % info_offset)
    
    info = version_info.from_buffer(raw_data, info_offset)
    
    if info.image_crc and not args.force:
        raise Exception("already filled out")

    fill_version_info(info)
    
    info.image_size = len(raw_data)
    info.image_crc = CRC32().forge(
        args.crc, str(raw_data), 
        info_offset + info.offsetof_image_crc
    )

    dprint("  image_crc  = 0x%08x" % info.image_crc)
    dprint("  image_size = %d" % info.image_size)

    ##########

    dprint("saving \"%s\"..." % args.target)

    with open(args.target, "wb") as f:
        f.write(raw_data)


def patch_elf():
    dprint("loading \"%s\"..." % args.source)

    with open(args.source, "rb") as f:
        elf_data = bytearray(f.read())

    elf = elf_reader.ELFObject.from_string(elf_data)
    for s in elf.sections:
        dprint("  %-16s: 0x%08x -> 0x%08x %8d" % (s.name, s.lma, s.sh_addr, s.sh_size))

    ##########

    dprint("searching for structure marker...")

    for info_section in elf.sections:
        info_offset = find_info_offset(info_section.data)
        if info_offset >= 0:
            break
    else:
        raise Exception("structure marker not found")

    dprint("  found in %s at %d" % (info_section.name, info_offset))

    info = version_info.from_buffer(info_section.data, info_offset)
    
    if info.image_crc and not args.force:
        raise Exception("already filled out")

    fill_version_info(info)

    info.image_start = elf.sections[0].lma
    info.image_size = elf.sections[-1].lma + elf.sections[-1].sh_size - elf.sections[0].lma

    info.image_crc = CRC32().forge(
        args.crc, str(elf.to_bin()),
        info_section.lma - elf.sections[0].lma +
        info_offset + info.offsetof_image_crc
    )

    dprint("  image_crc   = 0x%08x" % info.image_crc)
    dprint("  image_start = 0x%08x" % info.image_start)
    dprint("  image_size  = %d" % info.image_size)

    ##########

    dprint("saving \"%s\"..." % args.target)

    with open(args.target, "wb") as f:
        f.write(elf_data)


if __name__ == '__main__':
    try:
        parse_args()
        
        if (args.raw):
            patch_raw()
        else:
            patch_elf()

    except Exception as e:
        sys.stderr.write("error: %s\n" % e)
        exit(1)
