import os
CURDIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = "C:/workdir/logs/"
IMMUNITY_PATH = r"C:\Program Files\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = os.path.join(CURDIR, os.pardir, os.pardir, 'samples')
DEPLOY_DIR = os.path.join(CURDIR, os.pardir, os.pardir, 'deploy')
RAW_DIR = os.path.join(CURDIR, os.pardir, os.pardir, 'logs')
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

F_CLSCTX = {0x1: 'CLSCTX_INPROC_SERVER',
            0x2: 'CLSCTX_INPROC_HANDLER',
            0x4: 'CLSCTX_LOCAL_SERVER',
            0x8: 'CLSCTX_INPROC_SERVER16',
            0x10: 'CLSCTX_REMOTE_SERVER',
            0x20: 'CLSCTX_INPROC_HANDLER16',
            0x400: 'CLSCTX_NO_CODE_DOWNLOAD',
            0x1000: 'CLSCTX_NO_CUSTOM_MARSHAL',
            0x2000: 'CLSCTX_ENABLE_CODE_DOWNLOAD',
            0x4000: 'CLSCTX_NO_FAILURE_LOG',
            0x8000: 'CLSCTX_DISABLE_AAA',
            0x10000: 'CLSCTX_ENABLE_AAA',
            0x20000: 'CLSCTX_FROM_DEFAULT_CONTEXT',
            0x40000: 'CLSCTX_ACTIVATE_32_BIT_SERVER',
            0x80000: 'CLSCTX_ACTIVATE_64_BIT_SERVER',
            0x100000: 'CLSCTX_ENABLE_CLOAKING',
            0x400000: 'CLSCTX_APPCONTAINER',
            0x800000: 'CLSCTX_ACTIVATE_AAA_AS_IU',
            0x80000000: 'CLSCTX_PS_DLL'}

CLSIDS = {'{D20EA4E1-3957-11d2-A40B-0C5020524153}': 'Administrative Tools',
          '{ED7BA470-8E54-465E-825C-99712043E01C}': 'All Tasks',
          '{21EC2020-3AEA-1069-A2DD-08002b30309d}': 'Control Panel',
          '{241D7C96-F8BF-4F85-B01F-E2B043341A4B}': 'Connections',
          '{D20EA4E1-3957-11d2-A40B-0C5020524152}': 'Fonts',
          '{20D04FE0-3AEA-1069-A2D8-08002B30309D}': 'Computer',
          '{450D8FBA-AD25-11D0-98A8-0800361B1103}': 'Documents',
          '{ff393560-c2a7-11cf-bff4-444553540000}': 'History',
          '{208d2c60-3aea-1069-a2d7-08002b30309d}': 'Network Places',
          '{15eae92e-f17a-4431-9f28-805e482dafd4}': 'NetInstall',
          '{2227A280-3AEA-1069-A2DE-08002B30309D}': 'Printers and Faxes',
          '{7be9d83c-a729-4d97-b5a7-1b7313c39e0a}': 'Programs Folder',
          '{645FF040-5081-101B-9F08-00AA002F954E}': 'Recycle Bin',
          '{48e7caab-b918-4e58-a94d-505519c795dc}': 'Start Menu',
          '{D6277990-4C6A-11CF-8D87-00AA0060F5BF}': 'Scheduled Tasks',
          '{1D2680C9-0E2A-469d-B787-065558BC7D43}': 'Sert',
          '{78F3955E-3B90-4184-BD14-5397C15F1EFC}': 'WEI',
          '{4026492F-2F69-46B8-B9BF-5654FC07E423}': 'Brandmauer'}

          






