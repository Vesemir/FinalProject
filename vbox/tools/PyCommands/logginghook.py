from immlib import LogBpHook, Debugger
import struct
import random
import re
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from settings import LOGS_DIR, F_FILEOPEN, F_DESACCESS, F_SHAREMODE, F_FLANDATTRS


CURDIR = os.path.dirname(os.path.abspath(__file__))
FUNCTION = re.compile(r'At 0x[0-9a-f]{8} in (?P<libname>\w+) \(base \+ 0x[0-9a-f]{8}\) : (?P<funcaddr>0x[0-9a-f]{8}) \(ptr to (?P<funcname>[a-zA-Z0-9.]+)\)')

valid = re.compile(r'(?P<funcname>\w+)\n(?P<funcdesc>[A-Z].+?\.)\n', re.DOTALL)


def get_enabled_flags(fdict, flag):
    res = []
    for key, value in fdict.items():
        if flag & key:
            res.append(value)
    return '|'.join(res)


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
        """
        extraargs = dict()
        pos = regs['EIP']
        arg1 = self.imm.readLong(regs['ESP'] + 4)
        self.get_extra_args(extraargs, pos, regs)
        self.save_test_case(pos, arg1, extraargs)

    def get_extra_args(self, extra, pos, regs):
        tr = lambda x: x.split('\x00')[0]
        if 'loadlibrary' in self.fdict[pos]:
            p_libname = self.imm.readLong(regs['ESP'] + 4)
            if p_libname:
                extra['libname'] = tr(self.imm.readMemory(p_libname, 30))
        if 'getprocaddress' in self.fdict[pos]:
            p_funcname = self.imm.readLong(regs['ESP'] + 8)
            extra['funcname'] = tr(self.imm.readMemory(p_funcname, 30))
        if 'findfirstfile' in self.fdict[pos]:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            extra['filename'] = tr(self.imm.readMemory(p_filename, 30))
        if 'regopenkey' in self.fdict[pos]:
            p_regkey = self.imm.readLong(regs['ESP'] + 8)
            if p_regkey:
                extra['regkey'] = tr(self.imm.readMemory(p_regkey, 30))
        if 'findresource' in self.fdict[pos]:
            p_resource = self.imm.readLong(regs['ESP'] + 8)
            try: #  Microsoft says it can be some macros MAKEINTRESOURCESTRING
                extra['resource'] = tr(self.imm.readMemory(p_resource, 30))
            except: #  instead of string, dunno what will happen here
                extra['resource'] = p_resource
        if 'createdirectory' in self.fdict[pos]:
            p_dirname = self.imm.readLong(regs['ESP'] + 4)
            extra['dirname'] = tr(self.imm.readMemory(p_dirname, 30))
        if 'createsemaphore' in self.fdict[pos]:
            p_semaphore = self.imm.readLong(regs['ESP'] + 0x10)
            extra['name'] = tr(self.imm.readMemory(p_semaphore, 30))
        if 'messagebox' in self.fdict[pos]:
            p_text = self.imm.readLong(regs['ESP'] + 8)
            p_caption = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_text:
                extra['text'] = tr(self.imm.readMemory(p_text, 30))
            if p_caption:
                extra['caption'] = tr(self.imm.readMemory(p_caption, 30))
        if 'shellexecute' in self.fdict[pos]:
            p_operation = self.imm.readLong(regs['ESP'] + 8)
            p_file = self.imm.readLong(regs['ESP'] + 0x0c)
            p_params = self.imm.readLong(regs['ESP'] + 0x10)
            p_directory = self.imm.readLong(regs['ESP'] + 0x14)
            if p_operation:
                extra['operation'] = tr(self.imm.readMemory(p_operation, 30))
            if p_params:
                extra['params'] = tr(self.imm.readMemory(p_params, 30))
            if p_directory:
                extra['directory'] = tr(self.imm.readMemory(p_directory, 30))
            extra['file'] = tr(self.imm.readMemory(p_file, 30))
        if 'comparestring' in self.fdict[pos]:
            p_string1 = self.imm.readLong(regs['ESP'] + 0x0c)
            p_string2 = self.imm.readLong(regs['ESP'] + 0x14)
            if p_string1:
                extra['string1'] = tr(self.imm.readMemory(p_string1, 30))
            if p_string2:
                extra['string2'] = tr(self.imm.readMemory(p_string2, 30))
        if 'strcmp' in self.fdict[pos]:
            p_string1 = self.imm.readLong(regs['ESP'] + 4)
            p_string2 = self.imm.readLong(regs['ESP'] + 8)
            if p_string1:
                extra['string1'] = tr(self.imm.readMemory(p_string1, 30))
            if p_string2:
                extra['string2'] = tr(self.imm.readMemory(p_string2, 30))
        if 'strcpy' in self.fdict[pos]:
            p_srcstring = self.imm.readLong(regs['ESP'] + 8)
            if p_srcstring:
                extra['src_string'] = tr(self.imm.readMemory(p_srcstring, 30))
        if 'registerwindowsmessage' in self.fdict[pos]:
            p_message = self.imm.readLong(regs['ESP'] + 4)
            if p_message:
                extra['message'] = tr(self.imm.readMemory(p_message, 30))
        if 'lcmapstring' in self.fdict[pos]:
            p_srcstring = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_srcstring:
                extra['src_string'] = tr(self.imm.readMemory(p_srcstring, 30))
        if 'strlen' in self.fdict[pos]:
            p_string = self.imm.readLong(regs['ESP'] + 4)
            if p_string:
                extra['string'] = tr(self.imm.readMemory(p_string, 30))
        if 'openfile' in self.fdict[pos]:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = tr(self.imm.readMemory(p_filename, 40))
            style = self.imm.readLong(regs['ESP'] + 0x0C)
            extra['ustyle'] = get_enabled_flags(F_FILEOPEN, style)
        if 'createfile' in self.fdict[pos]:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = tr(self.imm.readMemory(p_filename, 40))
            d_access = self.imm.readLong(regs['ESP'] + 8)
            extra['desired_access'] = get_enabled_flags(F_DESACCESS, d_access)
            share_mode = self.imm.readLong(regs['ESP'] + 0x0C)
            extra['share_mode'] = get_enabled_flags(F_SHAREMODE, share_mode)
            attrs = self.imm.readLong(regs['ESP'] + 0x18)
            extra['flags_and_attrs'] = get_enabled_flags(F_FLANDATTRS, attrs)
                
    def save_test_case(self, pos, arg1, more):
        message = "*****\n"
        message += "IN : %s\n" % self.fdict[pos]
        if len(more) != 0:
            message += '\n'.join(
                "LOOKING UP {}: {}".format(
                    key, value)
                for key, value in more.items()
                )
        #message += "ARG1 : 0x%08x\n" % arg1
        message += "\n*****\n"
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
