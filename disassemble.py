#!/usr/bin/env python3

import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from elftools.common.exceptions import ELFError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import argparse

if __name__ == "__main__":
    print('****************************************')
    print('* disassemble.py                       *')
    print('****************************************')

    parser = argparse.ArgumentParser(
                        prog='disassemble.py',
                        description='A tool for inspecting the .text section of elf files',
                        epilog='jpm 2023')
    parser.add_argument('filename',
                        type=str,
                        help='the file or path to file that you wish to inspect')
    args = parser.parse_args()

#    if len(sys.argv) < 2:
#        sys.exit('(disassemble.py) EXIT: please provide an elf binary file')
        
    try:
        file = open(args.filename, "rb")
        rawcode = file.read()
        print(rawcode[:20])
    except FileNotFoundError:
        print('(disassemble.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        print('(disassemble.py) EXCEPTION: file can not be opened, it is a directory')
    except ELFError:
    	print('(disassemble.py) EXCEPTION: file has encountered an elf error')
    #except None:
    #    print('(disassemble.py) EXCEPTION: Null value encountered')
    else:
        print(f'(disassemble.py) RUN: {file.name} opened, loading ELF data...')
        try:
            elffile = ELFFile(file)
        except elftools.common.exceptions.ELFError:
    	    print('(disassemble.py) EXCEPTION: file has encountered an elf error')
     #   except None:
     #       print('(disassemble.py) EXCEPTION: Null value encountered')
        else:
            print(f'(disassemble.py) RUN: ELFFile loaded, searching for .text...')
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for segment in elffile.iter_segments():
                segh = segment.header
                for section_idx in range(elffile.num_sections()):
                    section = elffile.get_section(section_idx)
                    #print(f'Section: {section.name}, Type: {segh.p_type}')
                    if section.name == '.text':
                        print(f'(disassemble.py) RUN: .text section found, disassembling...')
                        print(section.data)
                        for i in md.disasm(rawcode, section.offset):
                            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                        
                        #use this to find offset then use md.disasm at that offset
    print('****************************************')
        
