import os
import ctypes
import win32com.client
import subprocess
import time

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

IMMUNITY_PATH = r"C:\Program Files (x86)\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = r"C:\Program Files (x86)\Immunity Inc\Immunity Debugger\loaddll.exe"
ENGLISH_LAYOUT = b'00000409'
LOGS_DIR = "Q:/logs/"


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
        

def rundebuggee():
    print("[!] Running debuggee ..")
    subprocess.Popen([IMMUNITY_PATH, SAMPLE_PATH])
    time.sleep(3)
    print("[+] Done.")


def executePyCommands():
    sample_name = os.path.basename(SAMPLE_PATH)
    logpath = os.path.join(LOGS_DIR, os.path.splitext(sample_name)[0])
    
    def PyCommand(string):
        SHELL.SendKeys(string + '~')
        time.sleep(5)
        
    SHELL = win32com.client.Dispatch("WScript.Shell")
    SHELL.AppActivate("Immunity Debugger -")
    SHELL.SendKeys("%{F1}")
    check_layout(SHELL)
    PyCommand("!mona config -set workingfolder " + LOGS_DIR + "{%}p")
    SHELL.SendKeys("%{F1}")
    PyCommand("!mona getiat -s kernel32.*")
    SHELL.SendKeys("%{F1}")
    PyCommand("!mona bf -t ADD -f import -s kernel32.*")
    SHELL.SendKeys("%{F1}")
    PyCommand("!logginghook %s" % logpath)
    for _ in range(100):
        time.sleep(1)
        SHELL.SendKeys("{F9}")
    

def main():
    rundebuggee()
    executePyCommands()
    

if __name__ == '__main__':
    main()
