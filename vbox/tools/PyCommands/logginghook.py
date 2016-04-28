from immlib import LoadDLLHook, LogBpHook, Debugger
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
from mona import MnCommand, MnConfig, MnModule, MnPointer, MnLog


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from settings import LOGS_DIR, F_FILEOPEN, F_DESACCESS, F_SHAREMODE
from settings import F_CLSCTX, F_FLANDATTRS, F_MOVFLAGS


CURDIR = os.path.dirname(os.path.abspath(__file__))
FUNCTION = re.compile(r'At 0x[0-9a-f]{8} in (?P<libname>\w+) \(base \+ 0x[0-9a-f]{8}\) : (?P<funcaddr>0x[0-9a-f]{8}) \(ptr to (?P<funcname>[a-zA-Z0-9.]+)\)')


#ripped off from mona
arch = 32


def toHex(n):
    if arch == 32:
        return "%08x" % n
    if arch == 64:
        return "%016x" % n


def setconfig():
    monaConfig = MnConfig()
    configparam, configvalue = 'workingfolder', LOGS_DIR + "%p"
    monaConfig.set(configparam,configvalue)


def populateModuleInfo(dbg):
    g_modules={}
    allmodules=dbg.getAllModules()
    curmod = ""
    for key in allmodules.keys():
        modinfo={}
        thismod = MnModule(key)
        if not thismod is None:
            modinfo["path"]     = thismod.modulePath
            modinfo["base"]     = thismod.moduleBase
            modinfo["size"]     = thismod.moduleSize
            modinfo["top"]      = thismod.moduleTop
            modinfo["safeseh"]  = thismod.isSafeSEH
            modinfo["aslr"]     = thismod.isAslr
            modinfo["nx"]       = thismod.isNX
            modinfo["rebase"]   = thismod.isRebase
            modinfo["version"]  = thismod.moduleVersion
            modinfo["os"]       = thismod.isOS
            modinfo["name"]     = key
            modinfo["entry"]    = thismod.moduleEntry
            modinfo["codebase"] = thismod.moduleCodebase
            modinfo["codesize"] = thismod.moduleCodesize
            modinfo["codetop"]  = thismod.moduleCodetop
            g_modules[thismod.moduleKey] = modinfo
        else:
            dbg.log("    - Oops, potential issue with module %s, skipping module" % key)
    dbg.log("    - Done. Let's rock 'n roll.")
    dbg.setStatusBar("")
    dbg.updateLog()
    return g_modules


def getModulesToQuery(imm):
    g_modules = populateModuleInfo(imm)
    modulestoquery=[]
    for thismodule,modproperties in g_modules.iteritems():
        thismod = MnModule(thismodule)
        modulestoquery.append(thismod.moduleKey)
    return modulestoquery


def procGetxAT(dbg, mode='iat'):
    keywords = []
    keywordstring = ""
    
    criteria = {}
    thisxat = {}
    entriesfound = 0

    keywordstring = 'kernel32.*,user32.*,shell32.*,advapi32.*,wsock32.*,oleaut32.*'# gdi32.*,samcli.*,apphelp.*,

    keywords = keywordstring.split(",")

    criteria["accesslevel"] = "X"

    
    modulestosearch = getModulesToQuery(dbg)
    dbg.log("[+] Querying %d modules" % len(modulestosearch))

    if len(modulestosearch) > 0:
        xatfilename="%ssearch.txt" % mode
        objxatfilename = MnLog(xatfilename)
        xatfile = objxatfilename.reset()

        for thismodule in modulestosearch:
            thismod = MnModule(thismodule)
            thisxat = thismod.getIAT()
            thismodule = thismod.getShortName()

            for thisfunc in thisxat:
                thisfuncname = thisxat[thisfunc].lower()
                origfuncname = thisfuncname
                firstindex = thisfuncname.find(".")
                if firstindex > 0:
                    thisfuncname = thisfuncname[firstindex+1:len(thisfuncname)]
                addtolist = False
                iatptr_modname = ""
                modinfohr = ""
                               
                theptr = struct.unpack('<L',dbg.readMemory(thisfunc,4))[0]
                ptrx = MnPointer(theptr)
                iatptr_modname = ptrx.belongsTo()
                if not iatptr_modname == "" and "." in iatptr_modname:
                    iatptr_modparts = iatptr_modname.split(".")
                    iatptr_modname = iatptr_modparts[0]
                if not "." in origfuncname and iatptr_modname != "" and not "!" in origfuncname:
                    origfuncname = iatptr_modname.lower() + "." + origfuncname
                    thisfuncname = origfuncname

                if "!" in origfuncname:
                    oparts = origfuncname.split("!")
                    origfuncname = iatptr_modname + "." + oparts[1]
                    thisfuncname = origfuncname

                try:
                    ModObj = MnModule(iatptr_modname)
                    modinfohr = " - %s" % (ModObj.__str__())
                except:
                    modinfohr = ""
                    pass

                if len(keywords) > 0:
                    for keyword in keywords:
                        keyword = keyword.lower().strip()
                        if ((keyword.startswith("*") and keyword.endswith("*")) or keyword.find("*") < 0):
                            keyword = keyword.replace("*","")
                            if thisfuncname.find(keyword) > -1:
                                addtolist = True
                                break
                        if keyword.startswith("*") and not keyword.endswith("*"):
                            keyword = keyword.replace("*","")
                            if thisfuncname.endswith(keyword):
                                addtolist = True
                                break
                        if keyword.endswith("*") and not keyword.startswith("*"):
                            keyword = keyword.replace("*","")
                            if thisfuncname.startswith(keyword):
                                addtolist = True
                                break
                else:
                    addtolist = True
                if addtolist:
                    entriesfound += 1
                    # add info about the module

                    thedelta = thisfunc - thismod.moduleBase
                    logentry = "At 0x%s in %s (base + 0x%s) : 0x%s (ptr to %s) %s" % (toHex(thisfunc),thismodule.lower(),toHex(thedelta),toHex(theptr),origfuncname,modinfohr)
                    
                    dbg.log(logentry,address = thisfunc)
                    objxatfilename.write(logentry,xatfile)
        dbg.log("")
        dbg.log("%d entries found" % entriesfound)
#/rip

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


def function_dict(path):
    f_dict = dict()
    with open(path) as inp:
        for eachfunc in FUNCTION.finditer(inp.read()):
            temp = eachfunc.groupdict()
            f_dict[int(temp['funcaddr'], 16)] = temp['funcname']
    return f_dict


class ExportHook(LoadDLLHook):
    def __init__(self, fdict, logspath):
        LoadDLLHook.__init__(self)
        self.imm = Debugger()
        self.hooker = CallGetter(fdict, logspath)

    def run(self, regs):
        event = self.imm.getEvent()
        p_modulename = event.lpImageName
        modulename = self.imm.readWString(p_modulename)
        self.imm.log("Module got loaded : {}".format(modulename))
        module = self.imm.getModule(modulename)
        self.imm.analyseCode(module.getCodebase())
        extra_funcs = self.imm.getAllFunctions(module.getCodebase())
        for funcaddr in extra_funcs:
            function = self.imm.getFunction(funcaddr)
            funcname = self.imm.decodeAddress(func)
            self.hooker.add(funcname, funcaddr)


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
        truncator = self.imm.readWString if bp_decoded.endswith('w')\
                    else self.imm.readString
        self.get_extra_args(extraargs, pos, bp_decoded, regs, truncator)
        self.save_test_case(pos, arg1, extraargs)

    def get_extra_args(self, extra, pos, bp_decoded, regs, read_str):
        extra['callname'] = bp_decoded
        if 'loadlibrary' in bp_decoded:
            p_libname = self.imm.readLong(regs['ESP'] + 4)
            if p_libname:
                extra['libname'] = read_str(p_libname)
                self.imm.runTillRet()
                module = self.imm.getModule(extra['libname'].lower())
                if module:
                    if not module.isAnalysed():
                        self.imm.analyseCode(module.getCodebase())
        elif 'getprocaddress' == bp_decoded.split('.')[1]:
            p_funcname = self.imm.readLong(regs['ESP'] + 8)
            fname = read_str(p_funcname).lower()
            if not fname.isalpha():
                fname = '<ordinal>: {}'.format(p_funcname % 0x10000)
            extra['funcname'] = fname
            #self.imm.runTillRet()
            #newregs = self.imm.getRegs()
            #faddr = newregs['EAX']
            #if faddr and fname.isalpha() and not 'rtl' in fname: # according to MSDN returns address of fucntion
                #self.fdict[faddr] = fname.lower()
                #functions_hooker = CallGetter(self.fdict, self.logfile)
                #functions_hooker.add(fname, faddr) # doc said I know what I'm doing
                #self.imm.log("Added bp on {} for {}".format(faddr, fname))
        
        elif 'movefile' in bp_decoded:
            p_src = self.imm.readLong(regs['ESP'] + 4)
            p_dest = self.imm.readLong(regs['ESP'] + 8)
            extra['src'] = read_str(p_src)
            if p_dest:
                extra['dest'] = read_str(p_dest)
            if 'ex' in bp_decoded:
                movflags = self.imm.readLong(regs['ESP'] + 0x0c)
                extra['flags'] = get_enabled_flags(F_MOVFLAGS, movflags)
            if 'progress' in bp_decoded:
                movflags = self.imm.readLong(regs['ESP'] + 0x14)
                extra['flags'] = get_enabled_flags(F_MOVFLAGS, movflags)           
        elif 'findfirstfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            extra['filename'] = read_str(p_filename)
        elif 'regopenkey' in bp_decoded:
            p_regkey = self.imm.readLong(regs['ESP'] + 8)
            if p_regkey:
                extra['regkey'] = read_str(p_regkey)
        elif 'regsetvalue' in bp_decoded:
            p_subkey = self.imm.readLong(regs['ESP'] + 8)
            if p_subkey:
                extra['regkey'] = read_str(p_subkey)
            p_value = self.imm.readLong(regs['ESP'] + 0x10)
            extra['value'] = read_str(p_value)
        elif 'regcreatekey' in bp_decoded:
            p_regkey = self.imm.readLong(regs['ESP'] + 8)
            extra['regkey'] = read_str(p_regkey)
        elif 'findresource' in bp_decoded:
            p_resource = self.imm.readLong(regs['ESP'] + 8)
            try: #  Microsoft says it can be some macros MAKEINTRESOURCESTRING
                extra['resource'] = read_str(p_resource)
            except: #  instead of string, dunno what will happen here
                extra['resource'] = p_resource
        elif 'cocreateinstance' in bp_decoded:
            clsctx = self.imm.readLong(regs['ESP'] + 0x0c)
            extra['clsctx'] = get_enabled_flags(F_CLSCTX, clsctx)
        elif 'createdirectory' in bp_decoded:
            p_dirname = self.imm.readLong(regs['ESP'] + 4)
            extra['dirname'] = read_str(p_dirname)
        elif 'httpsendrequest' in bp_decoded:
            l_headers = self.imm.readLong(regs['ESP'] + 0x0c)
            if l_headers != 0:
                const = 50 if l_headers == -1 else l_headers
                p_headers = self.imm.readLong(regs['ESP'] + 0x08)
                extra['headers'] = read_str(p_headers)
            l_opt = self.imm.readLong(regs['ESP'] + 0x14)
            if l_opt != 0:
                const = 50 if l_opt == -1 else l_opt
                p_opt = self.imm.readLong(regs['ESP'] + 0x08)
                extra['optional'] = read_str(p_opt)
        elif 'createsemaphore' in bp_decoded:
            p_semaphore = self.imm.readLong(regs['ESP'] + 0x10)
            extra['name'] = read_str(p_semaphore)
        elif 'messagebox' in bp_decoded:
            p_text = self.imm.readLong(regs['ESP'] + 8)
            p_caption = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_text:
                extra['text'] = read_str(p_text)
            if p_caption:
                extra['caption'] = read_str(p_caption)
        elif 'shellexecute' in bp_decoded:
            p_operation = self.imm.readLong(regs['ESP'] + 8)
            p_file = self.imm.readLong(regs['ESP'] + 0x0c)
            p_params = self.imm.readLong(regs['ESP'] + 0x10)
            p_directory = self.imm.readLong(regs['ESP'] + 0x14)
            if p_operation:
                extra['operation'] = read_str(p_operation)
            if p_params:
                extra['params'] = read_str(p_params)
            if p_directory:
                extra['directory'] = read_str(p_directory)
            extra['file'] = read_str(p_file)
        elif 'comparestring' in bp_decoded:
            p_string1 = self.imm.readLong(regs['ESP'] + 0x0c)
            p_string2 = self.imm.readLong(regs['ESP'] + 0x14)
            if p_string1:
                extra['string1'] = read_str(p_string1)
            if p_string2:
                extra['string2'] = read_str(p_string2)
        elif 'strcmp' in bp_decoded:
            p_string1 = self.imm.readLong(regs['ESP'] + 4)
            p_string2 = self.imm.readLong(regs['ESP'] + 8)
            if p_string1:
                extra['string1'] = read_str(p_string1)
            if p_string2:
                extra['string2'] = read_str(p_string2)
        elif 'strcpy' in bp_decoded:
            p_srcstring = self.imm.readLong(regs['ESP'] + 8)
            if p_srcstring:
                extra['src_string'] = read_str(p_srcstring)
        elif 'registerwindowsmessage' in bp_decoded:
            p_message = self.imm.readLong(regs['ESP'] + 4)
            if p_message:
                extra['message'] = read_str(p_message)
        elif 'lcmapstring' in bp_decoded:
            p_srcstring = self.imm.readLong(regs['ESP'] + 0x0c)
            if p_srcstring:
                extra['src_string'] = read_str(p_srcstring)
        elif 'strlen' in bp_decoded:
            p_string = self.imm.readLong(regs['ESP'] + 4)
            if p_string: # there are probably null bytes in strlenW gotta check
                extra['string'] = read_str(p_string)
        elif 'querydirectoryfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 0x28)
            if p_string: # there are probably null bytes in strlenW gotta check
                extra['filename'] = read_str(p_filename)
        elif 'openfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = read_str(p_filename)
            style = self.imm.readLong(regs['ESP'] + 0x0C)
            extra['ustyle'] = get_enabled_flags(F_FILEOPEN, style)
        elif 'createfile' in bp_decoded:
            p_filename = self.imm.readLong(regs['ESP'] + 4)
            if p_filename:
                extra['filename'] = read_str(p_filename)
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
    #ntdll = imm.getModule('ntdll.dll')
    #kernel32 = imm.getModule('kernel32.dll')
    #imm.analyseCode(ntdll.getCodebase())
    #if kernel32:
    #    imm.analyseCode(kernel32.getCodebase())
    
    setconfig()
    procGetxAT(imm)
    logspath = args[0]
    path = os.path.join(logspath, "iatsearch.txt")
    functions_dict = function_dict(path)
    #loaddll_hook = ExportHook(functions_dict, logspath) # doesn't work 
    #loaddll_hook.add("Generic DLL handler")
    functions_hooker = CallGetter(functions_dict, logspath)
    dump = ''
    for address, funcname in functions_dict.items():
        #if not 'rtl' in funcname:
        functions_hooker.add(funcname, address)
    return "[*] API calls hooker enabled!"
