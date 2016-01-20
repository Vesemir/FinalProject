import pandas as pd
import numpy as np
from pandas import DataFrame
import os
import sys
import glob
import funcparserlib.parser as p
import pickle
from collections import deque
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from vbox.tools.PyCommands.settings import RAW_DIR

CURDIR = os.path.dirname(os.path.abspath(__file__))
MAPPING = os.path.join(CURDIR, 'funcmapping.pk')
SVM_LOGS = os.path.join(CURDIR, 'svm_analyzer', 'datas')
SEQ_LOGS = os.path.join(CURDIR, 'seq_analyzer', 'datas')

for each in (SVM_LOGS, SEQ_LOGS):
    if not os.path.isdir(each):
        os.makedirs(each)
punctuation = (':', ' ', '.', '\n', '\\', '_', '{', '}', '-')

lexem = p.some(lambda x: x.isalpha() or x.isdigit() or x in punctuation)

endl = p.skip(p.maybe(p.a('\n')))
stars = p.skip(p.oneplus(p.a('*')))

concat = (lambda seq: ''.join(seq))

def sequence_to_list(src):
    if isinstance(src, str):
        array = np.load(src)
    elif isinstance(src, (deque, list, tuple)):
        array = src
    if not os.path.isfile(MAPPING):
        print('[-] No mapping found to convert ..')
        sys.exit(1)
    with open(MAPPING, 'rb') as inp:
        mapping = pickle.load(inp)
        print("[!] Succesfully loaded mapping")
    revmapping = {value: key for (key, value) in mapping.items()}
    return ' -> '.join(revmapping.get(each, 'Unk') for each in array)        


def dframe_to_sequence(dframe, filename='sample'):
    print('Working with \n', dframe)
    current = []
    if not os.path.isfile(MAPPING):
        print("[-] No mapping found, creating new one ...")
        mapping = dict()
    else:
        print("[+] Found ready mapping, loading ...")
        with open(MAPPING, 'rb') as inp:
            mapping = pickle.load(inp)
            print("[!] Loaded : {}".format(mapping))
    for func in zip(dframe['dllname'], dframe['call']):
        record = '.'.join(func)
        query_mapping = mapping.get(record)
        if query_mapping:
            print("[!] Using cached value of {}".format(record))
            current.append(query_mapping)
        else:
            print("[!] Got new func : {}".format(record))
            curlen = len(mapping) + 1
            current.append(curlen)
            mapping[record] = curlen
    print(mapping)
    results = np.asarray(current)
    print('[!] Saving {}\'s results to file'.format(filename))
    np.save(os.path.join(SEQ_LOGS, filename), results)
    print("[!] Dumping renewed mapping back to file")
    with open(MAPPING, 'wb') as outp:
        pickle.dump(mapping, outp)


def tuplicate(onecall):
    retval = dict()
    sequence = [val for val in onecall.split('\n') if val]
    call = sequence.pop(0).split(':')[1].strip()
    lib, func = call.split('.')
    retval['dllname'] = lib
    retval['call'] = func
    for extraarg in sequence:
        sep_pos = extraarg.find(':')
        if sep_pos != -1:
            name, value = extraarg[:sep_pos], extraarg[sep_pos+1:]
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


def calc_agg(name, lis):
    print(lis)
    grouped = lis.groupby('call').size()
    grouped.to_pickle(os.path.join(SVM_LOGS, name))
    print('[+] Pickled SVM log for {}'.format(name))


@coroutine
def sink():
    while True:
        name, df = yield
        calc_agg(name, df)
        dframe_to_sequence(df, filename=name)
        
    

@coroutine
def fileparse(target):
    while True:
        filepath = yield
        print('[!] There are logs for {} sample'.format(filepath))
        with open(filepath) as raw:
            buff = raw.read().replace('\x00', ' ')
            reslist = manycalls.parse(buff)
            samplename = os.path.basename(os.path.dirname(filepath))
            if reslist:
                target.send((samplename, DataFrame(reslist)))
            else:
                assert False, 'LOOK EHRE : {}'.format(samplename.upper())
                print("[-] Could not be parsed {}".format(samplename))


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
    
        
