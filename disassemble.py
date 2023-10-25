#!/usr/bin/env python3

import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
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
                        help='the file or path to file that you wish to inspect')
    args = parser.parse_args()

    try:
        file = open(args.filename, "rb")
    except FileNotFoundError:
        print('(disassemble.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        print('(disassemble.py) EXCEPTION: file can not be opened, it is a directory')
    except None:
        print('(disassemble.py) EXCEPTION: Null value encountered')
    else:
        print(f'(disassemble.py) RUN: {args.filename} opened, disassembling...')
        #file is now populated with an elf file
        for segment in ELFFile(file).iter_segments():
            segh = segment.header
            print(f'Segment: {segment.section.name}, Type: {segh.p_type}')

        
