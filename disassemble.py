import os
import sys
import elftools
import argparse

if __name__ == "__main__":
    print('****************************************')
    print('* disassemble.py                       *')
    print('****************************************')

    parser = argparse.ArgumentParser(
                        prog='disassemble.py',
                        description='A tool for inspecting the .text section of executables',
                        epilog='jpm 2023')
    parser.add_argument('filename',
                        help='the file or path to file that you wish to inspect')
    args = parser.parse_args()
    fileName = args.filename

    try:
        file = open(fileName, "rb")
    except FileNotFoundError:
        print('(disassemble.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        print('(disassemble.py) EXCEPTION: file can not be opened, it is a directory')
    except None:
        print('(disassemble.py) EXCEPTION: Null value encountered')
    else:
        print(f'(disassemble.py) RUN: {fileName} opened, disassembling...')
        data = file.read()
        
        
