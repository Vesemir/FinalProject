import vboxapi
#this one should complete a routine:
## Take a sample from samples/ directory
#1. Start Linux host from clear prepared snapshot + 
#2. Start Windows host from clear prepared snapshot
#3. Download sample executable to Windows host
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

def startVM(name='INetSim'):
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    machine_ctrl = session.machine
    snap = machine.findSnapshot('Working INetSIM')
    progress = machine_ctrl.restoreSnapshot(snap)
    progress.waitForCompletion(-1)
    session.unlockMachine()
    print('[+] Snapshot for {} restored'.format(name))
    session = vbmanager.mgr.getSessionObject(VBOX)
    progress = machine.launchVMProcess(session, 'headless', '')
    progress.waitForCompletion(-1)
    session.unlockMachine()
    print('[+] Machine {} started.'.format(name))
        

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
