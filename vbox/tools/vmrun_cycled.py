import vboxapi
import os
import sys
import glob
import time
import threading
import queue
import pathlib
import glob
from contextlib import contextmanager
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
CURDIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(CURDIR, os.pardir, os.pardir))
from vbox.tools.drawer import draw_samples
from vbox.tools.PyCommands.settings import LOGS_DIR as VMLOGS_DIR
from vbox.tools.PyCommands.settings import IMMUNITY_PATH
from vbox.tools.PyCommands.settings import SAMPLE_PATH

from vbox.tools.PyCommands.settings import DEPLOY_DIR
CHUNKSIZE = 4096


PYTHON = r'C:/Python27/python.exe'

WINVM = 'TempOS'
LOGIN = 'One'
PASSWORD = '1'
LINUXVM = 'INET_SIM'

WORK_TIMEOUT = 120000

IMMUNITY_DIR = os.path.join(os.path.dirname(IMMUNITY_PATH), 'PyCommands')
MONA = os.path.join(IMMUNITY_DIR, 'mona.py')
LOGS_PATH = os.path.join(CURDIR, os.pardir, 'logs')
KIT_DIR = 'PyCommands'
KIT = ('getapilog.py',
       'logginghook.py',
       'settings.py',
       'API_USAGE.txt',
       'zipper.py',
       )
GETAPI = 'getapilog.py'

PRINT_LOCK = threading.Semaphore(1)
AGENT_POOL = queue.Queue()




vbmanager = vboxapi.VirtualBoxManager(None, None)
CONST = vbmanager.constants
VBOX = vbmanager.vbox
REMOTE = vbmanager.remote
LOG_LEVEL = 'debug'

LEVELS = {'debug': 1,
          'trace': 0}

_agent = lambda x, y, z, t: dict(name=x, login=y, password=z, snapshot=t)


@contextmanager
def safeprint(lock):
    lock.acquire()
    yield
    lock.release()


def newprint(val, level='debug', *args, **kwargs):
    with safeprint(PRINT_LOCK):
        if LEVELS.get(level) >= LEVELS.get(LOG_LEVEL):
            oldprint(val, *args, **kwargs)


def startVM(name=LINUXVM, style='headless', snapshot='Working INetSIM'):
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
    print('[+] Machine {} started'.format(name))


def copytoolstoVM(name=WINVM,
                  dest_dir='C:/foo', username=None, password=None):
    print('[!] Copying toolkit for debuggee...', 'trace')
    for tool in KIT:
        toolpath = os.path.join(CURDIR, KIT_DIR, tool)
        copyfiletoVM(name=name,
                     src_file=toolpath, dest_dir=IMMUNITY_DIR,
                     username=username, password=password)
        if any(val in toolpath for val in ('settings', 'getapilog', 'zipper')):
            copyfiletoVM(name=name,
                         src_file=toolpath, dest_dir=dest_dir,
                         username=username, password=password)
    print('[+] Done.', level='trace')


def deploytoolstoVM(dest_dir='C:/foo'):
    print('[!] Deploying tools ...', level='trace')
    for packet in glob.glob(os.path.join(DEPLOY_DIR, '*')):
        if not 'tar.gz' in packet:
            copyfiletoVM(src_file=packet, dest_dir=dest_dir)
    print('[+] Done.', level='trace')


def copyfiletoVM(name=WINVM,
                 src_file='Q:\compilers\decompilation_thesis.pdf',
                 dest_dir='C:/fuu/',
                 username=LOGIN,
                 password=PASSWORD):
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
            src_file, name, dest_file), level='trace'
              )
    except Exception as e:
        print("[-] Couldn't create specified file {} on {} machine, {}".format(
            dest_file, name, str(e))
              )
    finally:
        mysession.close()
        session.unlockMachine()


def readfilefromVM(name=WINVM,
                   src_file='C:/fuu/log.txt',
                   dest_dir='Q:/compilers/',
                   username=LOGIN,
                   password=PASSWORD):
    success = None
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
        success = True
    except Exception as e:
        print("[-] Couldn't read specified file {} on {} machine, {}".format(
            src_file, name, str(e))
              )
        success = False
    finally:
        mysession.close()
        session.unlockMachine()
        return success


def runprocessonVM(name=WINVM,
                   dest_file='C:/Windows/notepad.exe',
                   args='',
                   username=LOGIN,
                   password=PASSWORD,
                   work_dir='',
                   timeoutMS=60000):
    argarray = ['']
    if args != '':
        argarray = ['', args['command'], args['file']]
    print("[!] Running command :  {} {}".format(dest_file, ' '.join(argarray)),
          level='trace')
    machine = VBOX.findMachine(name)
    session = vbmanager.openMachineSession(machine)
    guest = session.console.guest
    mysession = guest.createSession(username, password, '', session)
    print("[!] Protocol version of VBService is {}".format(
        mysession.protocolVersion), level='trace')
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
            dest_file, process.PID), level='trace'
              )
        res = process.WaitFor(CONST.ProcessWaitForFlag_Terminate, timeoutMS)
        if res not in (CONST.ProcessWaitResult_Terminate,
                       CONST.ProcessWaitResult_Timeout):
            raise Exception("[-] Unknown status {}".format(res))
        print('[+] Succesfully terminated process {}'.format(
            dest_file), level='trace'
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
    session.unlockMachine()
    print('[+] Machine {} stopped'.format(name))


def run_sample(samplepath, adict=_agent('TempOS_1', 'One', '1', 'masquedmore'),
               timeout=WORK_TIMEOUT, work_dir='C:/workdir'):
    proc_name = os.path.basename(samplepath)
    sample_log = os.path.join(LOGS_PATH,
                              os.path.splitext(proc_name)[0])
    try:
        
        agent, login, password, snapshot = \
               adict['name'], adict['login'], adict['password'], adict['snapshot']
                
        startVM(name=agent, style='headless', snapshot=snapshot)
        copytoolstoVM(name=agent,
                      dest_dir=work_dir,
                      username=login,
                      password=password)
        copyfiletoVM(name=agent,
                     src_file=samplepath,
                     dest_dir=work_dir,
                     username=login,
                     password=password)
        getapi = os.path.join(work_dir, GETAPI)
        runprocessonVM(name=agent,
                       dest_file=PYTHON,
                       work_dir=work_dir,
                       args=dict(
                           command=getapi,
                           file=os.path.join(
                               work_dir, proc_name
                               )
                           ),
                       timeoutMS=timeout,
                       username=login,
                       password=password)
        cur_log = os.path.join(VMLOGS_DIR,
                               os.path.splitext(proc_name)[0],
                               'apicalls.log')
        cur_search = os.path.join(VMLOGS_DIR,
                               os.path.splitext(proc_name)[0],
                               'iatsearch.txt')
        
        if not os.path.isdir(sample_log):
            os.makedirs(sample_log)
        done = readfilefromVM(name=agent,
                              username=login,
                              password=password,
                              src_file=cur_log, dest_dir=sample_log)
        readfilefromVM(name=agent,
                       src_file=cur_search,
                       dest_dir=sample_log,
                       username=login,
                       password=password)
        #os.rename(samplepath, os.path.splitext(samplepath, [0]) + '.done')
        
    except:
        pass
    finally:
        freezeVM(name=agent)
        AGENT_POOL.put(adict)
    return os.path.join(sample_log, 'apicalls.log')

        
def dirty_hacks():
    doer = glob.iglob(os.path.join(LOGS_PATH, '*'))
    for logpath in doer:
        targetfile = os.path.join(SAMPLE_PATH, os.path.basename(logpath) + '.zip')
        if os.path.isfile(targetfile):
           print("renaming one")
           os.rename(os.path.join(SAMPLE_PATH, os.path.basename(logpath) + '.zip'),
                     os.path.join(SAMPLE_PATH, os.path.basename(logpath) + '.done'))
            
            
            
def run_cycled(agents_num=10, samples_num=65536, sample_dir=SAMPLE_PATH):
    draw_samples(src='MalShare', num=samples_num)
    start_time = time.time()
    print('[!] Started run at {}'.format(time.ctime()))
    startVM(name=LINUXVM, snapshot='fixed')
    pool = [_agent('TempOS_%d' % idx, 'One', '1', 'masquedmore')
            for idx in range(1, agents_num + 1)]
    for agent in pool:
        AGENT_POOL.put(agent)
    job_pool = glob.glob(os.path.join(sample_dir, '*.zip'))
    WORK_SIZE = len(job_pool)
    thread_pool = []
    while job_pool:
        try:
            print('[!] Job size left : {}'.format(len(job_pool)))
            ready_agent = AGENT_POOL.get(timeout=15)
            to_wait = [each for each in thread_pool
                       if each.name == ready_agent['name']]
            if to_wait:
                print("[!] Waiting for thread {} to finish ...".format(to_wait[0]))
                to_wait[0].join()
                thread_pool.pop(thread_pool.index(to_wait[0]))
            print('[!] Got free agent: {}'.format(ready_agent))
            nextsample = job_pool.pop()
            work_thr = threading.Thread(
                name=ready_agent['name'],
                target=run_sample, args=(nextsample, ready_agent)
                )
            print('[!] Executing job on {}...'.format(ready_agent))
            work_thr.start()
            thread_pool.append(work_thr)
            time.sleep(8)
        except queue.Empty:
            print('[-] Out of agents, idling for now ...')            
    print('[!] Waiting everyone to finish ...')
    for thread in thread_pool:
        thread.join()
        print('[+] {} succesfully stopped'.format(thread))
    print('[+] Jobs are done!')
    took_time = time.time() - start_time
    print('[!] Finished run at {}, took {} minutes, done {} samples'.format(
        time.ctime(), took_time / 60, WORK_SIZE))
    freezeVM(LINUXVM)


if __name__ == '__main__':
    assert os.path.isdir(SAMPLE_PATH)
    assert os.path.isdir(LOGS_PATH)
    oldprint = __builtins__.print
    __builtins__.print = newprint
    run_cycled()
