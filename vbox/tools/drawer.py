import glob
import os
import shutil


from PyCommands.settings import SAMPLE_PATH, VIRUS_SHARE, MAL_SHARE
from PyCommands.zipper import zipin

def filterPE(pfile):
    with open(pfile, 'rb') as candy:
        dec = candy.read(2)
        if dec != b'MZ':
            return False
        candy.seek(0x3c)
        pos = int.from_bytes(candy.read(4), 'little')
        candy.seek(pos)
        peheader = candy.read(4)
        if peheader != b'PE\x00\x00':
            return False
        platform = candy.read(2)
        if platform == b'\x64\x86':
            print('[-] {} is compiled for x64'.format(pfile))
            return False
        if platform != b'\x4c\x01':
            return False       
    return True


def draw_samples(src='VirusShare', num=100, suffix=''):
    if src == 'VirusShare':
        SOURCE_DIR = VIRUS_SHARE
    elif src == 'MalShare':
        SOURCE_DIR = MAL_SHARE
    elif src == 'VirusSign':
        SOURCE_DIR = VIRUS_SIGN # seems impossible to download any
    if suffix:
        SOURCE_DIR = os.path.join(SOURCE_DIR, suffix)
    print("[!] Drawing samples from {} ...".format(SOURCE_DIR))
    for eachfile in glob.glob(os.path.join(SOURCE_DIR, '*')):
        if filterPE(eachfile):
            print("[!] Copying {} to samples".format(eachfile))
            zipin(eachfile, targetdir=SAMPLE_PATH)
##            shutil.copy(eachfile,
##                        os.path.join(
##                            SAMPLE_PATH,
##                            os.path.basename(eachfile)
##                            ) +
##                        '.exe'
##                        )
            num -= 1
        if num < 1:
            break
    
