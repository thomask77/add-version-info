# Reader for 32 and 64 bit ELF files.
#
# Copyright (c)2018 Thomas Kindler <mail_git@t-kindler.de>
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
from ctypes import *

# see http://lxr.free-electrons.com/source/include/uapi/linux/elf.h

Elf32_Addr      = c_uint32
Elf32_Half      = c_uint16
Elf32_Off       = c_uint32
Elf32_Sword     = c_int32
Elf32_Word      = c_uint32

Elf64_Addr      = c_uint64
Elf64_Half      = c_uint16
Elf64_SHalf     = c_int16
Elf64_Off       = c_uint64
Elf64_Sword     = c_int32
Elf64_Word      = c_uint32
Elf64_Xword     = c_uint64
Elf64_Sxword    = c_int64

EI_MAG0         = 0
EI_MAG1         = 1
EI_MAG2         = 2
EI_MAG3         = 3
EI_CLASS        = 4
EI_DATA         = 5
EI_VERSION      = 6
EI_PAD          = 7
EI_NIDENT       = 16

ELFCLASSNONE    = 0
ELFCLASS32      = 1
ELFCLASS64      = 2

PT_NULL         = 0
PT_LOAD         = 1
PT_DYNAMIC      = 2
PT_INTERP       = 3
PT_NOTE         = 4
PT_SHLIB        = 5
PT_PHDR         = 6
PT_TLS          = 7

SHT_NULL        = 0
SHT_PROGBITS    = 1
SHT_SYMTAB      = 2
SHT_STRTAB      = 3
SHT_RELA        = 4
SHT_HASH        = 5
SHT_DYNAMIC     = 6
SHT_NOTE        = 7
SHT_NOBITS      = 8
SHT_REL         = 9
SHT_SHLIB       = 10
SHT_DYNSYM      = 11
SHT_NUM         = 12

SHF_WRITE       = 1
SHF_ALLOC       = 2
SHF_EXECINSTR   = 4


class elf32_hdr(Structure):
    _fields_ = [
        ("e_ident"      , c_char * EI_NIDENT),
        ("e_type"       , Elf32_Half),
        ("e_machine"    , Elf32_Half),
        ("e_version"    , Elf32_Word),
        ("e_entry"      , Elf32_Addr),
        ("e_phoff"      , Elf32_Off ),
        ("e_shoff"      , Elf32_Off ),
        ("e_flags"      , Elf32_Word),
        ("e_ehsize"     , Elf32_Half),
        ("e_phentsize"  , Elf32_Half),
        ("e_phnum"      , Elf32_Half),
        ("e_shentsize"  , Elf32_Half),
        ("e_shnum"      , Elf32_Half),
        ("e_shstrndx"   , Elf32_Half) 
    ]


class elf64_hdr(Structure):
    _fields_ = [
        ("e_ident"      , c_char * EI_NIDENT),
        ("e_type"       , Elf64_Half),
        ("e_machine"    , Elf64_Half),
        ("e_version"    , Elf64_Word),
        ("e_entry"      , Elf64_Addr),
        ("e_phoff"      , Elf64_Off ),
        ("e_shoff"      , Elf64_Off ),
        ("e_flags"      , Elf64_Word),
        ("e_ehsize"     , Elf64_Half),
        ("e_phentsize"  , Elf64_Half),
        ("e_phnum"      , Elf64_Half),
        ("e_shentsize"  , Elf64_Half),
        ("e_shnum"      , Elf64_Half),
        ("e_shstrndx"   , Elf64_Half)
    ]


class elf32_phdr(Structure):
    _fields_ = [
        ("p_type"       , Elf32_Word),
        ("p_offset"     , Elf32_Off ),
        ("p_vaddr"      , Elf32_Addr),
        ("p_paddr"      , Elf32_Addr),
        ("p_filesz"     , Elf32_Word),
        ("p_memsz"      , Elf32_Word),
        ("p_flags"      , Elf32_Word),
        ("p_align"      , Elf32_Word)
    ]


class elf64_phdr(Structure):
    _fields_ = [
        ("p_type"       , Elf64_Word ),
        ("p_flags"      , Elf64_Word ),
        ("p_offset"     , Elf64_Off  ),
        ("p_vaddr"      , Elf64_Addr ),
        ("p_paddr"      , Elf64_Addr ),
        ("p_filesz"     , Elf64_Xword),
        ("p_memsz"      , Elf64_Xword),
        ("p_align"      , Elf64_Xword)
    ]


class elf32_shdr(Structure):
    _fields_ = [
        ("sh_name"      , Elf32_Word),
        ("sh_type"      , Elf32_Word),
        ("sh_flags"     , Elf32_Word),
        ("sh_addr"      , Elf32_Addr),
        ("sh_offset"    , Elf32_Off ),
        ("sh_size"      , Elf32_Word),
        ("sh_link"      , Elf32_Word),
        ("sh_info"      , Elf32_Word),
        ("sh_addralign" , Elf32_Word),
        ("sh_entsize "  , Elf32_Word)
    ]


class elf64_shdr(Structure):
    _fields_ = [
        ("sh_name"      , Elf64_Word ),
        ("sh_type"      , Elf64_Word ),
        ("sh_flags"     , Elf64_Xword),
        ("sh_addr"      , Elf64_Addr ),
        ("sh_offset"    , Elf64_Off  ),
        ("sh_size"      , Elf64_Xword),
        ("sh_link"      , Elf64_Word ),
        ("sh_info"      , Elf64_Word ),
        ("sh_addralign" , Elf64_Xword),
        ("sh_entsize "  , Elf64_Xword)
    ]


class ELFException(Exception):
    pass


class ELFObject:
    @classmethod
    def from_bytes(cls, data):
        # Check for ELF32 or ELF64 signature
        #
        if data[EI_MAG0:EI_MAG3 + 1] != b'\x7fELF':
            raise ELFException("ELF signature not found")

        if data[EI_CLASS] == ELFCLASS32:
            elf_hdr = elf32_hdr
            elf_phdr = elf32_phdr
            elf_shdr = elf32_shdr
        elif data[EI_CLASS] == ELFCLASS64:
            elf_hdr = elf64_hdr
            elf_phdr = elf64_phdr
            elf_shdr = elf64_shdr
        else:
            raise ELFException("format not supported")

        obj = ELFObject()

        # Load ELF header
        #
        obj.header = elf_hdr.from_buffer(data)

        # Load segments
        #
        obj.segments = []
        for i in range(obj.header.e_phnum):
            p = elf_phdr.from_buffer(data, i * sizeof(elf_phdr) + obj.header.e_phoff)
            obj.segments.append(p)

        # Load sections
        #
        obj.sections = []
        for i in range(obj.header.e_shnum):
            s = elf_shdr.from_buffer(data, i * sizeof(elf_shdr) + obj.header.e_shoff)

            # Add data (if any)
            #
            if s.sh_type != SHT_NOBITS:
                s.data = (c_char * s.sh_size).from_buffer(data, s.sh_offset)

            # Find program segment and calculate load memory address 
            #
            for p in obj.segments:
                if p.p_vaddr <= s.sh_addr and p.p_vaddr + p.p_memsz >= s.sh_addr + s.sh_size:
                    s.lma = s.sh_addr + p.p_paddr - p.p_vaddr
                    break
            else:
                s.lma = s.sh_addr

            obj.sections.append(s)

        # Extract section names
        #
        offset = addressof(obj.sections[obj.header.e_shstrndx].data)
        for s in obj.sections:
            s.name = string_at(offset + s.sh_name)

        # Only keep code and data sections
        #
        obj.sections = [s for s in obj.sections
            if s.sh_flags & SHF_ALLOC
            and s.sh_type != SHT_NOBITS
        ]

        return obj

    def to_bin(self, gap_fill=0xff):
        bin_data = bytearray()
        for s in self.sections:
            gap = (s.lma - self.sections[0].lma) - len(bin_data)
            bin_data += bytes([gap_fill] * gap)
            bin_data += s.data

        return bin_data
