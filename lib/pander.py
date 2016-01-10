import pandas as pd
import numpy as np
from pandas import DataFrame
import os
import sys
import glob
import funcparserlib.parser as p
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from vbox.tools.PyCommands.settings import RAW_DIR

lexem = p.some(lambda x: x.isalpha() or x.isdigit() or x in (':', ' ', '.', '\n'))

endl = p.skip(p.maybe(p.a('\n')))
stars = p.skip(p.oneplus(p.a('*')))

concat = (lambda seq: ''.join(seq))

def tuplicate(onecall):
    retval = dict()
    sequence = [val for val in onecall.split('\n') if val]
    call = sequence.pop(0).split(':')[1].strip()
    lib, func = call.split('.')
    retval['dllname'] = lib
    retval['call'] = func
    for extraarg in sequence:
        name, value = extraarg.split(':')
        name = name.replace('LOOKING UP', '').strip()
        retval[name] = value.strip()
    return retval
    

singlecall = stars + endl +\
             p.oneplus(lexem) +\
             stars + endl >> concat >> tuplicate

manycalls = p.many(singlecall + endl)

             
def coroutine(func):
    def wrapper(*args, **kwargs):
        wrap = func(*args, **kwargs)
        next(wrap)
        return wrap
    return wrapper

def calc_agg(lis):
    print(lis.groupby('call').size())

@coroutine
def sink():
    totallist = []
    while True:
        df = yield
        totallist.append(df)
        calc_agg(df)
    

@coroutine
def fileparse(target):
    while True:
        filepath = yield
        print('[!] There are logs for {} sample'.format(filepath))
        with open(filepath) as raw:
            buff = raw.read()
            reslist = manycalls.parse(buff)
            target.send(DataFrame(reslist))


def raw_files(logdir, fileparser):
    ctr = 0
    for sample in glob.glob(os.path.join(logdir, '*')):
        logfil = os.path.join(sample, 'apicalls.log')
        if os.path.isfile(logfil):
            
            ctr += 1
            fileparser.send(logfil)
    print('[!] A total of {} logfiles present'.format(ctr))

def main():
    raw_files(RAW_DIR, fileparse(sink()))

if __name__ == '__main__':
    main()
        
