import os
import sys
import elftools
import argparse

if __name__ == "__main__":
    print('****************************************')
    print('* disassemble.py                       *')
    print('****************************************')

    numArgs = len(sys.argv)
    print('numArgs: ', numArgs, " ",sys.argv)
    if numArgs == 2:
        fileName = sys.argv[1] # Filename if defined on commandline
    elif numArgs < 2:
	    fileName = input('(disassemble.py) Please specify a file: ')
    elif numArgs > 2:
        sys.exit('(disassemble.py) EXIT: too many arguments\n')
    else:
        sys.exit('(disassemble.py) EXIT: undefined behavior\n')

    try:
        file = open(fileName, "rb")
    except FileNotFoundError:
        print('(disassemble.py) EXCEPTION: file can not be opened, not found')
    except IsADirectoryError:
        print('(disassemble.py) EXCEPTION: file can not be opened, it is a directory')
    except None:
        print('(disassemble.py) EXCEPTION: Null value encountered')
    else:
        print('(disassemble.py) RUN:',filename,' opened, disassembling...')
        
