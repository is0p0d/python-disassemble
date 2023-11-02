#!/usr/bin/env python3

#Jim M 2023
#CSC6580 - HW6

import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
'''a function for finding main within the .text section of an ELF file'''
def main_finder(elffile):
    mode = Cs(CS_ARCH_X86, CS_MODE_64)
    mode.detail = True
    dottext = elffile.get_section_by_name('.text')
    instructions = mode.disasm(dottext.data(), dottext.header['sh_addr'])
    inststack = [] #to gather instructions
    for inst in instructions:
        inststack.append(inst) #gather block
        if inst.mnemonic == 'call':
            nxinst = next(instructions)
            if nxinst.mnemonic in ['hlt', 'endbr64']: #checking for the end of the block
                for back in inststack: #doesnt work
                    #figure out how to walk backwards, maybe going address-by-address?
                    prvinst = inststack.pop()
                    if prvinst.mnemonic in ['mov', 'lea'] and 'rdi' in prvinst.op_str:
                        prvinst.mnemonic.split()[-1]
                        if 'rip' in prvinst.op_str: #rip addressing
                            # print(f'0x{prvprvinst.address:x}: {prvprvinst.mnemonic} {prvprvinst.op_str}')
                            # print(f'0x{prvinst.address:x}: {prvinst.mnemonic} {prvinst.op_str}')
                            offset = split_rip(prvinst.op_str)
                            offset = int(offset, 16)
                            #print(hex(offset))
                            print(hex(prvprvinst.address-offset))
                            #print(prvinst.detail.operands.mem.disp)
                        else:
                            absol = split_absolute(prvinst.op_str)
                            absol = int(absol, 16)
                            print(hex(absol))
                        return 0
                    prvprvinst = prvinst
    return -1 
def split_rip(operand):
    parts = operand.split('[')  # Split on the '[' character
    rip_relative_part = parts[1].strip(']')  # Remove the ']' character from the second part
    offset_parts = rip_relative_part.split('-')  # Split on the '-' character

    if len(offset_parts) > 1: 
        offset_value = offset_parts[1].strip()  # The offset value is the second part
        return offset_value
    else:
        return -1
def split_absolute(operand):
    parts = operand.split('[')
    if len(parts) > 1:
        return parts[1].strip(']')
    else:
        return -1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('(main.py) EXIT: please provide an elf binary file as your only argument')
    
    try:
        file = ELFFile(open(sys.argv[1], "rb"))
        if file is None:
            sys.exit('(main.py) EXIT: file is none')
        #rawcode = file.read()
    except FileNotFoundError:
        sys.exit('(main.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        sys.exit('(main.py) EXCEPTION: file can not be opened, it is a directory')
    except ELFError:
    	sys.exit('(main.py) EXCEPTION: file has encountered an elf error')
    else:
        if main_finder(file) != 0:
            sys.exit('(main.py) EXIT: cannot find main')