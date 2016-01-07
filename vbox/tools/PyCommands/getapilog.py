import os
import sys
import ctypes
import win32com.client
import win32gui
import win32process
import subprocess
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from zipper import zipout
from settings import LOGS_DIR, IMMUNITY_PATH
##
#python getapilog.py -> should do following things:
#C:/wherever_lies_immunity/ImmunityDebugger.exe <path_to_debuggee>->
#press <ALT+F1> -> print PyCommand(like in monaconfig.txt),
#*!mona config -set workingfolder Q:/somewhere/%p%i# %i for pid %p for process name
#^changes logs path to                  ^   that
#*!mona getiat -s * # dumps to logdir imported addresses
#*!mona bf -t ADD -f import -s <filter with wildcards *, ?> # shouldn't break on too many
#*!logginghook
#seems that typing need to be implemented by SendKeys, thus we need
#to probably check keyboard layout first like this:
#buff = ctypes.create_buffer_string(20)
#ctypes.windll.user2.GetKeyboardLayoutNameA(buff);
#assert buff.value == b'00000409'
##

ENGLISH_LAYOUT = b'00000409'


def unzip_sample(samplepath):
    zipout(samplepath)
    realname = os.path.splitext(samplepath)[0]
    os.rename(realname, realname + '.exe')


def check_layout(shell):
    print("[!] Checking keyboard layout")
    buff = ctypes.create_string_buffer(20)
    user32 = ctypes.windll.user32
    user32.GetKeyboardLayoutNameA(buff)
    if not buff.value == ENGLISH_LAYOUT:
        print("[-] Not english, trying to switch ...")
        shell.SendKeys("%+")
        user32.GetKeyboardLayoutNameA(buff)
        assert buff.value == ENGLISH_LAYOUT, "[-] Couldn't change layout"
    print("[+] Done.")          


def focusdebugger(pid):
    def callback(hwnd, hwnds):
        if win32gui.IsWindowVisible(hwnd) and win32gui.IsWindowEnabled(hwnd):
            _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
            if found_pid == pid:
                hwnds.append(hwnd)
        return True
    hwnds = []
    win32gui.EnumWindows(callback, hwnds)
    win32gui.SetForegroundWindow(hwnds[0])


def rundebuggee(sample):
    print("[!] Running debuggee ..")
    dbg = subprocess.Popen([IMMUNITY_PATH, sample])
    time.sleep(12)
    #focusdebugger(dbg.pid) doesn't work in vbox for some reason
    print("[+] Done.")


def executePyCommands(sample):
    sample_name = os.path.basename(sample)
    logpath = os.path.join(LOGS_DIR, os.path.splitext(sample_name)[0])
    
    def PyCommand(string):
        SHELL.SendKeys(string + '~')
                   
    SHELL = win32com.client.Dispatch("WScript.Shell")
    SHELL.SendKeys("%{Tab}")
    SHELL.AppActivate("Immunity Debugger")
    SHELL.SendKeys("%{F1}")
    #check_layout(SHELL)
    PyCommand("!hidedebug All_Debug")
    PyCommand("!hidedebug All_Process")
    PyCommand("!hidedebug All_Window")
    PyCommand("!mona config -set workingfolder " + LOGS_DIR + "{%}p")
    PyCommand("!mona getiat -s kernel32.*,user32.*,shell32.*")
    PyCommand("!mona bf -t ADD -f import -s kernel32.*,user32.*,shell32.*")
    PyCommand("!logginghook %s" % logpath)
    for _ in range(100):
        time.sleep(1)
        SHELL.SendKeys("{F9}")
    

def main():
    if not len(sys.argv) > 1:
        print("%usage: python getapilog.py <sample_file>")
        sys.exit(0)
    sample = sys.argv[1]
    unzip_sample(sample)
    sample_exe = os.path.splitext(sample)[0] + '.exe'
    rundebuggee(sample_exe)
    executePyCommands(sample_exe)
    

if __name__ == '__main__':
    main()
