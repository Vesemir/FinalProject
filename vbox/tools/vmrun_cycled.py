import vboxapi
import os
import glob
#this one should complete a routine:
## Take a sample from samples/ directory +
#1. Start Linux host from clear prepared snapshot + 
#2. Start Windows host from clear prepared snapshot +
#3. Download sample executable to Windows host # +
#4. Launch sample using Immunity Debugger scripts # should be working
#5. Wait ~ 2 min # +
#6. Terminate debugger # +
#7. Download Logs from Windows host # implemented using FileOpen
#7*. Download INetSIM logs -> but why ?.... # should check if 7 works for Linux
#8. Turn off both hosts. / -2 + 
##
from PyCommands.settings import LOGS_DIR as VMLOGS_DIR
from PyCommands.settings import IMMUNITY_PATH
CHUNKSIZE = 4096

CURDIR = os.path.dirname(os.path.abspath(__name__))
PYTHON = r'C:/Python27/python.exe'
IMMUNITY_DIR = os.path.join(os.path.dirname(IMMUNITY_PATH), 'PyCommands')
MONA = os.path.join(IMMUNITY_DIR, 'mona.py')
SAMPLE_PATH = os.path.join(CURDIR, os.pardir, 'samples')
LOGS_PATH = os.path.join(CURDIR, os.pardir, 'logs')
KIT_DIR = 'PyCommands'
KIT = ('getapilog.py', 'logginghook.py', 'settings.py', 'API_USAGE.txt')
GETAPI = 'getapilog.py'

vbmanager = vboxapi.VirtualBoxManager(None, None)
CONST = vbmanager.constants
VBOX = vbmanager.vbox
REMOTE = vbmanager.remote


assert os.path.isdir(SAMPLE_PATH)
assert os.path.isdir(LOGS_PATH)


def startVM(name='INetSim', style='headless', snapshot='Working INetSIM'):
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    machine_ctrl = session.machine
    snap = machine.findSnapshot(snapshot)
    progress = machine_ctrl.restoreSnapshot(snap)
    progress.waitForCompletion(-1)
    session.unlockMachine()
    print('[+] Snapshot for {} restored'.format(name))
    session = vbmanager.mgr.getSessionObject(VBOX)
    progress = machine.launchVMProcess(session, style, '')
    progress.waitForCompletion(-1)
    session.unlockMachine()
    print('[+] Machine {} started.'.format(name))


def copytoolstoVM(dest_dir='C:/foo'):
    print('[!] Copying toolkit for debuggee...')
    for tool in KIT:
        toolpath = os.path.join(CURDIR, KIT_DIR, tool)
        #assert False, (toolpath, dest_dir)
        copyfiletoVM(src_file=toolpath, dest_dir=IMMUNITY_DIR)
        if any(val in toolpath for val in ('settings', 'getapilog')):
            copyfiletoVM(src_file=toolpath, dest_dir=dest_dir)
        
        
    print('[+] Done.')


def copyfiletoVM(name='Candy',
                 src_file='Q:\compilers\decompilation_thesis.pdf',
                 dest_dir='C:/fuu/',
                 username='John',
                 password='123'):
    filename = os.path.basename(src_file)
    dest_file = os.path.join(dest_dir, filename)
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession(username, password, '', session)
    response = mysession.WaitFor(CONST.GuestSessionWaitForFlag_Start, 0)
    if response != 1:
        raise Exception("[-] Couldn't wait for session start")
    try:
        mysession.DirectoryCreate(dest_dir, 0o777, [CONST.DirectoryCreateFlag_Parents])
    except Exception as e:
        mysession.close()
        session.unlockMachine()
        raise Exception("[-] Couldn't create directory {}, {}".format(dest_dir, str(e)))
    try:
        pFile = mysession.FileOpen(
            dest_file,
            CONST.FileAccessMode_ReadWrite,
            CONST.FileOpenAction_CreateOrReplace,
            0o777)
        with open(src_file, 'rb') as inp:
            chunk = inp.read(CHUNKSIZE)
            while chunk:
                pFile.write(chunk, 0) #  0 for timeout
                chunk = inp.read(CHUNKSIZE)
        pFile.close()
        print('[+] Succesfully copied from host {} to {}\' {}'.format(
            src_file, name, dest_file)
              )
    except Exception as e:
        print("[-] Couldn't create specified file {} on {} machine, {}".format(
            dest_file, name, str(e))
              )
    finally:
        mysession.close()
        session.unlockMachine()


def readfilefromVM(name='Candy',
                   src_file='C:/fuu/log.txt',
                   dest_dir='Q:/compilers/',
                   username='John',
                   password='123'):
    filename = os.path.basename(src_file)
    dest_file = os.path.join(dest_dir, filename)
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession(username, password, '', session)
    response = mysession.WaitFor(CONST.GuestSessionWaitForFlag_Start, 0)
    try:
        pFile = mysession.FileOpen(
            src_file,
            CONST.FileAccessMode_ReadWrite,
            CONST.FileOpenAction_OpenExisting,
            0o777)
        sizeleft = pFile.seek(0, CONST.FileSeekOrigin_End)
        pFile.seek(0, CONST.FileSeekOrigin_Begin)
        with open(dest_file, 'wb') as outp:
            chunk = pFile.read(CHUNKSIZE, 0).tobytes() #  0 for timeout
            outp.write(chunk)
            sizeleft -= CHUNKSIZE
            while sizeleft > 0:
                chunk = pFile.read(CHUNKSIZE, 0)
                outp.write(chunk)
                sizeleft -= CHUNKSIZE
        pFile.close()
        print('[+] Succesfully copied to host {} from {}\'s {}'.format(
            dest_file, name, src_file)
              )
    except Exception as e:
        print("[-] Couldn't read specified file {} on {} machine, {}".format(
            src_file, name, str(e))
              )
    finally:
        mysession.close()
        session.unlockMachine()


def runprocessonVM(name='Candy',
                   dest_file='C:/Windows/notepad.exe',
                   args='',
                   username='John',
                   password='123',
                   work_dir='',
                   timeoutMS=60000):
    argarray = ['']
    if args != '':
        argarray = ['', args['command'], args['file']]
    print("[!] Running command :  {} {}".format(dest_file, ' '.join(argarray)))
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession(username, password, '', session)
    print("[!] Protocol version of VBService is {}".format(mysession.protocolVersion))
    response = mysession.WaitFor(CONST.GuestSessionWaitForFlag_Start, 0)
    try:
        if response != 1:
            raise Exception("[-] Couldn't wait for session start")
        process = mysession.ProcessCreate(
            dest_file,
            argarray, #  array of args, arg[1:] is passed to new process
            ["PATH=%s" % work_dir], #  environment changes - "VAR=VALUE" settting/ "VAR" unsetting
            [CONST.ProcessCreateFlag_None], # Wait for stdout - doesn't terminate
            #until all data is read, hidden - should be invisible to OS
            timeoutMS)
        process.WaitFor(CONST.ProcessWaitForFlag_Start, 0)
        print('[+] Succesfully started {} with PID {}'.format(
            dest_file, process.PID)
              )
        res = process.WaitFor(CONST.ProcessWaitForFlag_Terminate, timeoutMS)
        if res not in (CONST.ProcessWaitResult_Terminate,
                       CONST.ProcessWaitResult_Timeout):
            raise Exception("[-] Unknown status {}".format(res))
        print('[+] Succesfully terminated process {}'.format(
            dest_file)
              )
    except Exception as e:
        print("[-] Couldn't start specified file {} on {} machine, {}".format(
            dest_file, name, str(e))
              )
    finally:
        mysession.close()
        session.unlockMachine()
              
                
def freezeVM(name='INetSim'):
    machine = VBOX.findMachine(name)
    session = vbmanager.getSessionObject(VBOX)
    machine.lockMachine(session, CONST.LockType_Shared)
    if session.state != CONST.SessionState_Locked:
        session.unlockMachine()
        raise ValueError(
            'Session to {} is wrong state: {}'.format(
                name, session.state)
            )
    console = session.console
    progress = console.powerDown()
    progress.waitForCompletion(-1)
    print('[+] Machine {} stopped.'.format(name))


def run_cycled(work_dir='C:/workdir'):
    for eachsample in glob.glob(os.path.join(SAMPLE_PATH, '*.exe')):
        proc_name = os.path.basename(eachsample)
        startVM()
        startVM(name='Candy', style='headless', snapshot="butwhy")
        copytoolstoVM(dest_dir=work_dir)
        copyfiletoVM(src_file=eachsample, dest_dir=work_dir)
        getapi = os.path.join(work_dir, GETAPI)
        runprocessonVM(dest_file=PYTHON,
                       work_dir=work_dir,
                       args=dict(
                           command=getapi,
                           file=os.path.join(
                               work_dir, proc_name
                               )
                           ),
                       timeoutMS=180000)
        cur_log = os.path.join(VMLOGS_DIR,
                               os.path.splitext(proc_name)[0],
                               'apicalls.log')
        sample_log = os.path.join(LOGS_PATH, proc_name)
        readfilefromVM(src_file=cur_log, dest_dir=sample_log)
        freezeVM()
        freezeVM(name='Candy')
