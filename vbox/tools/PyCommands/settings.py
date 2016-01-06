import os
_CURDIR = os.path.dirname(os.path.abspath(__name__))
LOGS_DIR = "C:/workdir/logs/"
IMMUNITY_PATH = r"C:\Program Files (x86)\Immunity Inc\Immunity Debugger\ImmunityDebugger.exe"
SAMPLE_PATH = os.path.join(_CURDIR, os.pardir, 'samples')
VIRUS_SHARE = os.path.join(SAMPLE_PATH, 'VirusShare')
MAL_SHARE = os.path.join(SAMPLE_PATH, 'MalShare')
