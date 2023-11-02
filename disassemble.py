#!/usr/bin/env python3

#Jim M 2023
#CSC6580 - HW6

import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

if __name__ == "__main__":
    print()
    if len(sys.argv) != 2:
        sys.exit('(disassemble.py) EXIT: please provide an elf binary file as your only argument')
    
    try:
        file = ELFFile(open(sys.argv[1], "rb"))
        if file is None:
            sys.exit('(disassemble.py) EXIT: file is none')
        #rawcode = file.read()
    except FileNotFoundError:
        sys.exit('(disassemble.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        sys.exit('(disassemble.py) EXCEPTION: file can not be opened, it is a directory')
    except ELFError:
    	sys.exit('(disassemble.py) EXCEPTION: file has encountered an elf error')
    else:
        mode = Cs(CS_ARCH_X86, CS_MODE_64)
        dottext = file.get_section_by_name('.text')
        instructions = mode.disasm(dottext.data(), dottext.header['sh_addr'])
        for i in instructions:
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
