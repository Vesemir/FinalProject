import os
CURDIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = "C:/workdir/logs/"
IMMUNITY_PATH = r"C:\Program Files\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = os.path.join(CURDIR, os.pardir, os.pardir, 'samples')
DEPLOY_DIR = os.path.join(CURDIR, os.pardir, os.pardir, 'deploy')
VIRUS_SHARE = os.path.join(SAMPLE_PATH, 'VirusShare')
MAL_SHARE = os.path.join(SAMPLE_PATH, 'MalShare')
VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

F_FILEOPEN = {0x00000800: 'OF_CANCEL',
              0x00001000: 'OF_CREATE',
              0x00000200: 'OF_DELETE',
              0x00004000: 'OF_EXIST',
              0x00000100: 'OF_PARSE',
              0x00002000: 'OF_PROMPT',
              0x00000000: 'OF_READ',
              0x00000002: 'OF_READWRITE',
              0x00008000: 'OF_REOPEN',
              0x00000040: 'OF_SHARE_DENY_NONE',
              0x00000030: 'OF_SHARE_DENY_READ',
              0x00000020: 'OF_SHARE_DENY_WRITE',
              0x00000010: 'OF_SHARE_EXCLUSIVE',
              0x00000001: 'OF_WRITE'}

F_DESACCESS = {0x80000000: 'GENERIC_READ',
               0x40000000: 'GENERIC_WRITE',
               0x20000000: 'GENERIC_EXECUTE',
               0x10000000: 'GENERIC_ALL'}

F_SHAREMODE = {0x00000001: 'FILE_SHARE_READ',
               0x00000002: 'FILE_SHARE_WRITE',
               0x00000004: 'FILE_SHARE_DELETE'}

F_FLANDATTRS = {0x2: 'FILE_ATTRIBUTE_HIDDEN',
                0x1000: 'FILE_ATTRIBUTE_OFFLINE',
                0x1: 'FILE_ATTRIBUTE_READONLY',
                0x4: 'FILE_ATTRIBUTE_SYSTEM',
                0x100: 'FILE_ATTRIBUTE_TEMPORARY',
                0x20: 'FILE_ATTRIBUTE_ARCHIVE',
                0x04000000: 'FILE_FLAG_DELETE_ON_CLOSE',
                0x20000000: 'FILE_FLAG_NO_BUFFERING',
                0x80000000: 'FILE_FLAG_WRITE_THROUGH',
                0x10000000: 'FILE_FLAG_RANDOM_ACCESS',
                0x08000000: 'FILE_FLAG_SEQUENTIAL_SCAN',
                0x40000000: 'FILE_FLAG_OVERLAPPEND',
                0x02000000: 'FILE_FLAG_BACKUP_SEMANTICS'}

