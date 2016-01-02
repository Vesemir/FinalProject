import vboxapi
import os
import glob
#this one should complete a routine:
## Take a sample from samples/ directory
#1. Start Linux host from clear prepared snapshot + 
#2. Start Windows host from clear prepared snapshot
#3. Download sample executable to Windows host #DirectoryRemove works, at least
#4. Launch sample using Immunity Debugger scripts # should be working
#5. Wait ~ 2 min # same
#6. Terminate debugger # same
#7. Download Logs from Windows host # implement it as  download ?
#7*. Download INetSIM logs -> but why ?.... 
#8. Turn off both hosts. / -2 + 
##

vbmanager = vboxapi.VirtualBoxManager(None, None)
CONST = vbmanager.constants
VBOX = vbmanager.vbox
REMOTE = vbmanager.remote
SAMPLE_PATH = os.path.join(
    os.path.dirname(
        os.path.abspath(__name__)
        ),
    os.pardir,
    'samples')
assert os.path.isdir(SAMPLE_PATH)

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
            chunk = inp.read(4096)
            while chunk:
                pFile.write(chunk, 0) #  0 for timeout
                chunk = inp.read(4096)
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


def runprocessonVM(name='Candy',
                   dest_file='C:/Windows/notepad.exe',
                   arg='',
                   username='John',
                   password='123',
                   timeoutMS=60000):
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession(username, password, '', session)
    response = mysession.WaitFor(CONST.GuestSessionWaitForFlag_Start, 0)
    try:
        if response != 1:
            raise Exception("[-] Couldn't wait for session start")
        process = mysession.ProcessCreate(
            dest_file,
            ['', arg], #  array of args, arg[1:] is passed to new process
            [], #  environment changes - "VAR=VALUE" settting/ "VAR" unsetting
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
        startVM(name='Candy', style='gui', snapshot='WDKitInstalled')
        copyfiletoVM(src_file=eachsample, dest_dir=work_dir)
        runprocessonVM(dest_file=os.path.join(
            work_dir, os.path.basename(eachsample)
            ),
            timeoutMS=120000)
        freezeVM(name='Candy')
