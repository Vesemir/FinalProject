import os
CURDIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = "C:/workdir/logs/"
IMMUNITY_PATH = r"C:\Program Files\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = os.path.join(CURDIR, os.pardir, os.pardir, 'samples')
DEPLOY_DIR = os.path.join(CURDIR, os.pardir, os.pardir, 'deploy')
VIRUS_SHARE = os.path.join(SAMPLE_PATH, 'VirusShare')
MAL_SHARE = os.path.join(SAMPLE_PATH, 'MalShare')
VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
