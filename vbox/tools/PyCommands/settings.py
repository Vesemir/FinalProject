import os
_CURDIR = os.path.dirname(os.path.abspath(__name__))
LOGS_DIR = "C:/workdir/logs/"
IMMUNITY_PATH = r"C:\Program Files\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = os.path.join(_CURDIR, os.pardir, 'samples')
DEPLOY_DIR = os.path.join(_CURDIR, os.pardir, 'deploy')
VIRUS_SHARE = os.path.join(SAMPLE_PATH, 'VirusShare')
MAL_SHARE = os.path.join(SAMPLE_PATH, 'MalShare')
