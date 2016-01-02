import vboxapi
#this one should complete a routine:
## Take a sample from samples/ directory
#1. Start Linux host from clear prepared snapshot + 
#2. Start Windows host from clear prepared snapshot
#3. Download sample executable to Windows host #DirectoryRemove works, at least
#4. Launch sample using Immunity Debugger scripts
#5. Wait ~ 2 min
#6. Terminate debugger
#7. Download Logs from Windows host
#7*. Download INetSIM logs -> but why ?.... 
#8. Turn off both hosts. / -2 + 
##

vbmanager = vboxapi.VirtualBoxManager(None, None)
CONST = vbmanager.constants
VBOX = vbmanager.vbox
REMOTE = vbmanager.remote

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


def copyfiletoVM(name='Candy', src_file='Q:\compilers\decompilation_thesis.pdf',
                 dest_file='C:/fuu/decompile.pdf'):
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession('John', '123', '', session)
    response = mysession.WaitFor(CONST.GuestSessionWaitForFlag_Start, 0)
    if response != 1:
        raise Exception("[-] Couldn't wait for session start")
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
        session.unlockMachine()
              
                
def freezeVM(name='INetSim'):
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
