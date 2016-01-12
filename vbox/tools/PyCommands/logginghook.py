from immlib import LogBpHook, Debugger
import struct
import random
import re
import sys
import os

from hidedebug import (Patch_PEB, Patch_IsDebuggerPresent,
                       Patch_CheckRemoteDebuggerPresent,
                       Patch_ZwQueryInformationProcess,
                       Patch_GetTickCount,
                       Patch_ZwQuerySystemInformation,
                       Patch_FindWindow, Patch_EnumWindows)
from mona import MnCommand, MnConfig, MnModule

#MnCommand("config","Manage configuration file (mona.ini)",configUsage,procConfig,"conf")
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from settings import LOGS_DIR, F_FILEOPEN, F_DESACCESS, F_SHAREMODE
from settings import F_CLSCTX, F_FLANDATTRS, F_MOVFLAGS

IMPORTANT_FUNCTIONS = (
    'loadlibrary', 'getprocaddress', 'findfirstfile', 'regopenkey', 'findresource',
    'createdirectory', 'createsemaphore', 'messagebox', 'shellexecute', 'comparestring',
    'strcmp', 'strcpy', 'registerwindowsmessage', 'lcmapstring', 'strlen', 'openfile',
    'createfile'
    )
CURDIR = os.path.dirname(os.path.abspath(__file__))
FUNCTION = re.compile(r'At 0x[0-9a-f]{8} in (?P<libname>\w+) \(base \+ 0x[0-9a-f]{8}\) : (?P<funcaddr>0x[0-9a-f]{8}) \(ptr to (?P<funcname>[a-zA-Z0-9.]+)\)')

valid = re.compile(r'(?P<funcname>\w+)\n(?P<funcdesc>[A-Z].+?\.)\n', re.DOTALL)

trA = lambda x: x.split('\x00')[0]
trU = lambda x: x.split('\x00\x00')[0]


def setconfig():
    monaConfig = MnConfig()
    value = args["set"].split(" ")
    configparam = value[0].strip()
    dbg.log("Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
    configvalue = args["set"][0+len(configparam):len(args["set"])]
    monaConfig.set(configparam,configvalue)
    dbg.log("New value of parameter %s = %s" % (configparam,configvalue))

def hide(imm):
    Patch_PEB(imm)
    Patch_IsDebuggerPresent(imm)
    Patch_CheckRemoteDebuggerPresent(imm)
    Patch_ZwQueryInformationProcess(imm)
    Patch_GetTickCount(imm)
    Patch_ZwQuerySystemInformation(imm)
    Patch_FindWindow(imm)
    Patch_FindWindow(imm, suffix="W")
    Patch_FindWindow(imm, True, "A")
    Patch_FindWindow(imm, True, "W")
    Patch_EnumWindows(imm)
    

    

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
        bp_decoded = self.imm.decodeAddress(pos).lower()
        arg1 = self.imm.readLong(regs['ESP'] + 4)
        truncator = trU if bp_decoded.endswith('w') else trA
        self.get_extra_args(extraargs, pos, bp_decoded, regs, truncator)
        self.save_test_case(pos, arg1, extraargs)

    def get_extra_args(self, extra, pos, bp_decoded, regs, tr):
        
        extra['callname'] = bp_decoded
        if 'loadlibrary' in bp_decoded:
            p_libname = self.imm.readLong(regs['ESP'] + 4)
            if p_libname:
                extra['libname'] = tr(self.imm.readMemory(p_libname, 30))
        if 'getprocaddress' == bp_decoded.split('.')[1]:
            p_funcname = self.imm.readLong(regs['ESP'] + 8)
            fname = tr(self.imm.readMemory(p_funcname, 30))
            extra['funcname'] = fname
            self.imm.runTillRet()
            newregs = self.imm.getRegs()
            faddr = newregs['EAX']
            if faddr: # according to MSDN returns address of fucntion
                self.add("%08x" % faddr, faddr) # doc said I know what I'm doing
                self.fdict[faddr] = fname.lower()
                self.imm.log("Added bp on {} for {}".format(faddr, fname))
                #self.imm.setLoggingBreakpoint(faddr) # seems it is already added by .add
        if 'movefile' in bp_decoded:
            p_src = self.imm.readLong(regs['ESP'] + 4)
            p_dest = self.imm.readLong(regs['ESP'] + 8)
            extra['src'] = tr(self.imm.readMemory(p_src, 50))
            if p_dest:
                extra['dest'] = tr(self.imm.readMemory(p_dest, 50))
            if 'ex' in bp_decoded:
                movflags = self.imm.readLong(regs['ESP'] + 0x0c)
                extra['flags'] = get_enabled_flags(F_MOVFLAGS, movflags)
            if 'progress' in bp_decoded:
                movflags = self.imm.readLong(regs['ESP'] + 0x14)
                extra['flags'] = get_enabled_flags(F_MOVFLAGS, movflags)
                                   
                                   
            
            
        if 'findfirstfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            extra['filename'] = tr(self.imm.readMemory(p_filename, 60))
        if 'regopenkey' in bp_decoded:
            p_regkey = self.imm.readLong(regs['ESP'] + 8)
            if p_regkey:
                extra['regkey'] = tr(self.imm.readMemory(p_regkey, 80))
        if 'findresource' in bp_decoded:
            p_resource = self.imm.readLong(regs['ESP'] + 8)
            try: #  Microsoft says it can be some macros MAKEINTRESOURCESTRING
                extra['resource'] = tr(self.imm.readMemory(p_resource, 30))
            except: #  instead of string, dunno what will happen here
                extra['resource'] = p_resource
        if 'cocreateinstance' in bp_decoded:
            clsctx = self.imm.readLong(regs['ESP'] + 0x0c)
            extra['clsctx'] = get_enabled_flags(F_CLSCTX, clsctx)
        if 'createdirectory' in bp_decoded:
            p_dirname = self.imm.readLong(regs['ESP'] + 4)
            extra['dirname'] = tr(self.imm.readMemory(p_dirname, 30))
        if 'httpsendrequest' in bp_decoded:
            l_headers = self.imm.readLong(regs['ESP'] + 0x0c)
            if l_headers != 0:
                const = 50 if l_headers == -1 else l_headers
                p_headers = self.imm.readLong(regs['ESP'] + 0x08)
                extra['headers'] = tr(self.imm.readMemory(p_headers, const))
            l_opt = self.imm.readLong(regs['ESP'] + 0x14)
            if l_opt != 0:
                const = 50 if l_opt == -1 else l_opt
                p_opt = self.imm.readLong(regs['ESP'] + 0x08)
                extra['optional'] = tr(self.imm.readMemory(p_opt, const))
        if 'createsemaphore' in bp_decoded:
            p_semaphore = self.imm.readLong(regs['ESP'] + 0x10)
            extra['name'] = tr(self.imm.readMemory(p_semaphore, 30))
        if 'messagebox' in bp_decoded:
            p_text = self.imm.readLong(regs['ESP'] + 8)
            p_caption = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_text:
                extra['text'] = tr(self.imm.readMemory(p_text, 30))
            if p_caption:
                extra['caption'] = tr(self.imm.readMemory(p_caption, 30))
        if 'shellexecute' in bp_decoded:
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
        if 'comparestring' in bp_decoded:
            p_string1 = self.imm.readLong(regs['ESP'] + 0x0c)
            p_string2 = self.imm.readLong(regs['ESP'] + 0x14)
            if p_string1:
                extra['string1'] = tr(self.imm.readMemory(p_string1, 30))
            if p_string2:
                extra['string2'] = tr(self.imm.readMemory(p_string2, 30))
        if 'strcmp' in bp_decoded:
            p_string1 = self.imm.readLong(regs['ESP'] + 4)
            p_string2 = self.imm.readLong(regs['ESP'] + 8)
            if p_string1:
                extra['string1'] = tr(self.imm.readMemory(p_string1, 30))
            if p_string2:
                extra['string2'] = tr(self.imm.readMemory(p_string2, 30))
        if 'strcpy' in bp_decoded:
            p_srcstring = self.imm.readLong(regs['ESP'] + 8)
            if p_srcstring:
                extra['src_string'] = tr(self.imm.readMemory(p_srcstring, 60))
        if 'registerwindowsmessage' in bp_decoded:
            p_message = self.imm.readLong(regs['ESP'] + 4)
            if p_message:
                extra['message'] = tr(self.imm.readMemory(p_message, 30))
        if 'lcmapstring' in bp_decoded:
            p_srcstring = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_srcstring:
                extra['src_string'] = tr(self.imm.readMemory(p_srcstring, 30))
        if 'strlen' in bp_decoded:
            p_string = self.imm.readLong(regs['ESP'] + 4)
            if p_string: # there are probably null bytes in strlenW gotta check
                extra['string'] = tr(self.imm.readMemory(p_string, 60))
        if 'querydirectoryfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 0x28)
            if p_string: # there are probably null bytes in strlenW gotta check
                extra['filename'] = tr(self.imm.readMemory(p_filename, 60))
        if 'openfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = tr(self.imm.readMemory(p_filename, 40))
            style = self.imm.readLong(regs['ESP'] + 0x0C)
            extra['ustyle'] = get_enabled_flags(F_FILEOPEN, style)
        if 'createfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = tr(self.imm.readMemory(p_filename, 80))
            d_access = self.imm.readLong(regs['ESP'] + 8)
            extra['desired_access'] = get_enabled_flags(F_DESACCESS, d_access)
            share_mode = self.imm.readLong(regs['ESP'] + 0x0C)
            extra['share_mode'] = get_enabled_flags(F_SHAREMODE, share_mode)
            attrs = self.imm.readLong(regs['ESP'] + 0x18)
            extra['flags_and_attrs'] = get_enabled_flags(F_FLANDATTRS, attrs)
                
    def save_test_case(self, pos, arg1, more):
        message = "*****\n"
        message += "IN : %s\n" % more['callname']
        
        if len(more) != 0:
            message += '\n'.join(
                "LOOKING UP {}: {}".format(
                    key, value)
                for key, value in more.items()
                if key != 'callname'
                )
        #message += "ARG1 : 0x%08x\n" % arg1
        message += "\n*****\n"
        with open(self.logfile, "a") as fd:
            fd.write(message)
        
        
def main(args):
    imm = Debugger()
    hide(imm)
    logspath = args[0]
    path = os.path.join(logspath, "iatsearch.txt")
    functions_dict = function_dict(path)
    functions_hooker = CallGetter(functions_dict, logspath)
    imp_func = important_functions()
    dump = ''
    for address, funcname in functions_dict.items():
        if 'CmdLine' in funcname:
            print(address, funcname)
        #if funcname.split('.')[1] in imp_func:
        functions_hooker.add( "%08x" % address, address)
    return "[*] API calls hooker enabled!"
