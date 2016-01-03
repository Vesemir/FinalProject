from immlib import LogBpHook, Debugger
import struct
import random
import re
import sys
import os

sys.path.append(os.path.dirname(__file__))
from settings import LOGS_DIR

CURDIR = os.path.dirname(os.path.abspath(__file__))
FUNCTION = re.compile(r'At 0x[0-9a-f]{8} in (?P<libname>\w+) \(base \+ 0x[0-9a-f]{8}\) : (?P<funcaddr>0x[0-9a-f]{8}) \(ptr to (?P<funcname>[a-zA-Z0-9.]+)\)')

valid = re.compile(r'(?P<funcname>\w+)\n(?P<funcdesc>[A-Z].+?\.)\n', re.DOTALL)


def important_functions():
    with open(os.path.join(CURDIR, 'API_USAGE.txt')) as inp:
        wholedict = dict()
        whole = inp.read()
        for match in valid.finditer(whole):
            that = match.groupdict()
            that['funcdesc'] = that['funcdesc'].replace('\n', ' ')
            wholedict[that['funcname'].lower()] = that['funcdesc']
            #print('|{funcname}| """{funcdesc}"""'.format(**that))
    return wholedict


def function_dict(path):
    f_dict = dict()
    with open(path) as inp:
        for eachfunc in FUNCTION.finditer(inp.read()):
            temp = eachfunc.groupdict()
            f_dict[int(temp['funcaddr'], 16)] = temp['funcname']
    return f_dict


class CallGetter(LogBpHook):
    def __init__(self, func_dict, logspath):
        self.imm = Debugger()
        self.fdict = func_dict
        self.logfile = os.path.join(logspath, 'apicalls.log')
        LogBpHook.__init__(self)
        
    def run(self, regs):
        """
        We use the following offsets from the ESP register
        to trap the arguments to DeviceIoControl:
        ESP+4 -> hDevice arg1
        ESP+8 -> IoControlCode arg2 
        ESP+C -> InBuffer arg3
        ESP+10 -> InBufferSize arg4
        ESP+14 -> OutBuffer arg5
        ESP+18 -> OutBufferSize arg6
        ESP+1C -> pBytesReturned arg7
        ESP+20 -> pOverlapped
        """
        more = None
        # read the IOCTL code
        pos = regs['EIP']
        arg1 = self.imm.readLong(regs['ESP'] + 4)
        # read out the InBufferSize
        
        if 'getprocaddress' in self.fdict[pos]:
            p_funcname = self.imm.readLong(regs['ESP'] + 8)
            more = self.imm.readMemory(p_funcname, 30)
        # now we find the buffer in memory to mutate
        #inbuffer_ptr = self.imm.readLong(regs['ESP'] + 0xC) # 3rd arg is a pointer
        # grab the original buffer
        #in_buffer = self.imm.readMemory(inbuffer_ptr, inbuffer_size) #lets dereference it
        #mutated_buffer = self.mutate(inbuffer_size)
        # write the mutated buffer into memory
        # self.imm.writeMemory(inbuffer_ptr, mutated_buffer)
        # save the test case to file
        self.save_test_case(pos, arg1, more)
    
    def save_test_case(self, pos, arg1, more):
        message = "*****\n"
        message += "IN : %s\n" % self.fdict[pos]
        if more:
            message += "LOOKING UP: %s\n" % more.split('\x00')[0]
        message += "ARG1 : 0x%08x\n" % arg1
        message += "*****\n\n"
        with open(self.logfile, "a") as fd:
            fd.write(message)
        
        
def main(args):
    logspath = args[0]
    path = os.path.join(logspath, "iatsearch.txt")
    functions_dict = function_dict(path)
    imm = Debugger()
    functions_hooker = CallGetter(functions_dict, logspath)
    imp_func = important_functions()
    dump = ''
    for address, funcname in functions_dict.items():
        if 'CmdLine' in funcname:
            print(address, funcname)
        #if funcname.split('.')[1] in imp_func:
        functions_hooker.add( "%08x" % address, address)
    return "[*] API calls hooker enabled!"
