import os
from zipfile import ZipFile as Zip
from os.path import splitext as split


def zipin(filepath, targetdir=None):
    file = os.path.basename(filepath)
    if targetdir is None:
        targetdir = os.path.dirname(os.path.abspath(filepath))
    with Zip(os.path.join(targetdir, file + '.zip'), 'w') as outp:
        outp.write(filepath, arcname=file)

def zipout(zipfile, targetdir=None):
    if targetdir is None:
        targetdir = os.path.dirname(os.path.abspath(zipfile))
    filename = split(os.path.basename(zipfile))[0]
     
    with Zip(zipfile) as inp,\
         open(os.path.join(targetdir, filename), 'wb') as outp:
        outp.write(inp.read(filename))   
        



