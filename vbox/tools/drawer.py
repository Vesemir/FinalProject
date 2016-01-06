import glob
import os
import shutil


from PyCommands.settings import SAMPLE_PATH, VIRUS_SHARE, MAL_SHARE


def filterPE(pfile):
    with open(pfile, 'rb') as candy:
        dec = candy.read(2)
        if dec != b'MZ':
            return False
    return True


def draw_samples(src='VirusShare', num=100):
    if src == 'VirusShare':
        SOURCE_DIR = VIRUS_SHARE
    elif src == 'MalShare':
        SOURCE_DIR = MAL_SHARE
    
    print("[!] Drawing samples from {} ...".format(src))
    for eachfile in glob.glob(os.path.join(SOURCE_DIR, '*', '*')):
        if filterPE(eachfile):
            print("[!] Copying {} to samples".format(eachfile))
            shutil.copy(eachfile,
                        os.path.join(
                            SAMPLE_PATH,
                            os.path.basename(eachfile)
                            ) +
                        '.exe'
                        )
            num -= 1
        if num < 1:
            break
    
