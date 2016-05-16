import pandas as pd
import numpy as np
import h5py
from pandas import DataFrame
import os
import sys
import glob
import funcparserlib.parser as p
import logging
import json
import re
from collections import deque, OrderedDict
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from vbox.tools.PyCommands.settings import RAW_DIR, CLSIDS, \
     REG_BRANCHES, DANGEROUS_LIBS, F_MOVFLAGS, F_CLSCTX

CURDIR = os.path.dirname(os.path.abspath(__file__))
PARSE_LOG = os.path.join(CURDIR, 'parse_log.log')
MAPPING = os.path.join(CURDIR, 'funcmapping.json')
SVM_LOGS = os.path.join(CURDIR, 'svm_analyzer', 'datas')
SEQ_LOGS = os.path.join(CURDIR, 'seq_analyzer', 'datas')
KBASE_FILE = os.path.join(CURDIR, 'seq_analyzer', 'datas', 'knowledgebase.hdf5')
logging.basicConfig(filename=PARSE_LOG, level=logging.DEBUG)

for each in (SVM_LOGS, SEQ_LOGS):
    if not os.path.isdir(each):
        os.makedirs(each)


valid = re.compile(r'(?P<funcname>\w+)\n(?P<funcdesc>[A-Z].+?\.)\n', re.DOTALL)


def important_functions():
    with open(os.path.join(CURDIR, 'API_USAGE.txt')) as inp:
        wholedict = dict()
        whole = inp.read()
        for match in valid.finditer(whole):
            that = match.groupdict()
            that['funcdesc'] = that['funcdesc'].replace('\n', ' ')
            wholedict[that['funcname'].lower()] = that['funcdesc']
            #print('|{funcname}| """{funcdesc}"""'.format(**that))
    return wholedict


MORE_FUNCTIONS = set([
    'findfirstfile', 'createdirectory', 'createsemaphore',
    'messagebox', 'shellexecute', 'registerwindowsmessage',
    'lcmapstring', 'openfile', 'setinformationfile',
    ])


IMPORTANT_FUNCTIONS = set(important_functions().keys()
                          ).union(MORE_FUNCTIONS)

punctuation = (':', ' ', '.', '\n', '\\', '_', '{', '}', '-', '<', '>')

lexem = p.some(lambda x: x is not '*')#or x.isalpha() or x.isdigit() or x in punctuation)

endl = p.skip(p.maybe(p.a('\n')))
stars = p.skip(p.oneplus(p.a('*')))

concat = (lambda seq: ''.join(seq))


REGISTRY_MAPPING = {'HKLM': 'HKEY_LOCAL_MACHINE',
                    'HKCU': 'HKEY_CURRENT_USER'}


def find_reg_match(partial_path, reg_dict):
    for shortcut, path in REGISTRY_MAPPING.items():
        partial_path = partial_path.replace(
            shortcut, path
            )
    for key in reg_dict:
        if key.lower().endswith(partial_path.lower()):
            return key
    return ''


def extend_name(fname, series, imagename):
    if 'getprocaddress' in fname:
        if series.get('funcname') not in (None, np.nan, ''):
            name = series['funcname']
            if name.isalpha():
                if any(name.endswith(each) for each in ('A', 'W')):
                    name = name[:-1]
                fname += '.' + name.lower()
    elif 'loadlibrary' in fname:
        if series.get('libname') in DANGEROUS_LIBS:
            fname += '.' + DANGEROUS_LIBS[series['libname']]
    elif 'movefile' in fname:
        if series.get('flags') not in (None, np.nan, ''):
            fname += '.' + series['flags']
    elif any(each in fname for each in ('regopenkey',
                                      'regsetvalue',
                                      'regcreatekey')):
        if series.get('regkey') not in (None, np.nan, ''):          
            found = find_reg_match(series['regkey'], REG_BRANCHES)
            if found:
                fname += '.' + REG_BRANCHES[found]
            if imagename in series['regkey'].lower():
                
                fname += '.SelfImageName'
    elif 'createsemaphore' in fname:
        if series.get('name') not in (None, np.nan, ''):
            if imagename in series['name'].lower():
                fname += '.SelfImageName'
    elif any(each in fname for each in ('strcmp',
                                        'comparestring')):
        if series.get('string1') not in (None, np.nan, ''):
            if imagename in series['string1'].lower():
                fname += '.SelfImageName'
        if series.get('string2') not in (None, np.nan, ''):
            if imagename in series['string2'].lower():
                fname += '.SelfImageName'
    elif 'strcpy' in fname:
        if series.get('src_string') not in (None, np.nan, ''):
            if imagename in series['src_string'].lower():
                fname += '.SelfImageName'
    elif 'cocreateinstance' in fname:
        fname += '.' + series['clsctx']
    elif any(each in fname for each in ('createfile',
                                      'openfile',
                                      'findfirstfile',
                                      'querydirectoryfile')):
        if series.get('ustyle') not in (None, np.nan, ''):
            fname += '.' + series['ustyle']
        if series.get('desired_access') not in (None, np.nan, ''):
            fname += '.' + series['desired_access']
        if series.get('share_mode') not in (None, np.nan, ''):
            fname += '.' + series['share_mode']
        if series.get('flags_and_attrs') not in (None, np.nan, ''):
            fname += '.' + series['flags_and_attrs']
        if series.get('filename') not in (None, np.nan, ''):
            if 'Local\Temp' in series['filename']:
                fname += '.' + 'TempFile'
                        
    return fname


def find_call(call=None, call_name=None):
    with open(MAPPING, 'r') as inp, h5py.File(KBASE_FILE, driver='core') as dbase:
        mapping = json.load(inp)
        mapped_call = call_name and mapping[call_name]
        revmapping = {value: key for (key, value) in mapping.items()}
        db = dbase['knowledgebase']
        call_num = mapped_call or call
        for _hash in db:
            array = db[_hash]
            index = None
            for idx, val in enumerate(array):
                if call_num == val:
                    index = idx
            if index:
                if index > 10:
                    index = index - 10
                else:
                    index = 0
                print("[!] FOUND CALL IN {}!".format(_hash))
                print(' -> '.join(revmapping.get(each, 'Unk') if each != '-' else 'Skipped' for each in array[index:index+20]))                


def cached_mapping(func):
    with open(MAPPING, 'r') as inp:
        c_mapping = json.load(inp, object_pairs_hook=OrderedDict)
        rev_mapping = {value: key for (key, value) in c_mapping.items()}
        print("[!] Succesfully loaded mapping")        
    def retfunc(args, **kwargs):
        return func(args, mapping=c_mapping, revmapping=rev_mapping, **kwargs)        
    return retfunc
    

@cached_mapping
def sequence_to_list(src, mapping=None, revmapping=None):
    if isinstance(src, str):
        array = np.load(src)
    elif isinstance(src, (deque, list, tuple)):
        array = src
    if not os.path.isfile(MAPPING):
        print('[-] No mapping found to convert ..')
        sys.exit(1)
    result = ''
    prev_call = ''
    combo = 1
    for each in array:
        cur_call = revmapping.get(each) if each != 0 else 'Skipped'
        
        if prev_call != cur_call:
            result += ' -> ' + prev_call if combo == 1 else ' -> %dx ' % combo + prev_call
            combo = 1
        else:
            combo += 1
        prev_call = cur_call
    result += ' -> ' + cur_call if combo == 1 else ' -> %dx ' % combo + cur_call
    return result


def dframe_to_sequence(dframe, filename='sample', knowledge=None, mapping=None):
    #print('Working with \n', dframe)
    current = []
    
    for _, series in dframe.iterrows():
        record = '.'.join((series['dllname'], series['call']))
        if any(record.endswith(each) for each in ('a', 'w')):
            if not record.endswith('ow'):
                record = record[:-1]
        seq_name = extend_name(record, series, filename)
        query_mapping = mapping.get(seq_name)
        
        if query_mapping:
            #print("[!] Using cached value of {}".format(record))
            current.append(query_mapping)
        else:
            print("[!] Got new func : {}".format(seq_name))
            curlen = len(mapping) + 1
            current.append(curlen)
            mapping[seq_name] = curlen
    #print(mapping)
    
    results = np.asarray(current)
    #print('[!] Saving {}\'s results to file'.format(filename))
    knowledge.create_dataset(filename, data=results)
    

def tuplicate(onecall):
    retval = OrderedDict()
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
    grouped = lis.groupby('call').size()
    grouped.to_pickle(os.path.join(SVM_LOGS, name))
    #print('[+] Pickled SVM log for {}'.format(name))


@coroutine
def sink(kbase, mapping):
    while True:
        name, df = yield
        calc_agg(name, df)
        dframe_to_sequence(df, filename=name, knowledge=kbase, mapping=mapping)
 

@coroutine
def fileparse(target):
    while True:
        filepath = yield
        #print('[!] There are logs for {} sample'.format(filepath))
        with open(filepath, encoding='ascii', errors='ignore') as raw:
            buff = raw.read().replace('\x00', ' ')
            reslist = manycalls.parse(buff)
                       
            samplename = os.path.basename(os.path.dirname(filepath))
            if reslist:
                target.send((samplename,
                             DataFrame(reslist)
                             ))
            else:
                assert False, 'LOOK HERE : {}'.format(samplename.upper())
                print("[-] Could not be parsed {}".format(samplename))


def raw_files(logdir, fileparser):
    ctr = 0
    for sample in glob.glob(os.path.join(logdir, '*')):
        logfil = os.path.join(sample, 'apicalls.log')
        if ctr % 1000 == 0:
            print('[!] A total of {} logfiles processed'.format(ctr))
        if os.path.isfile(logfil):
            ctr += 1
            try:
                fileparser.send(logfil)
            except Exception as e:
                logging.debug("[!] Can't parse : {}, skipping. Reason : {}".format(sample, str(e)))
    print('[!] A total of {} logfiles present'.format(ctr))


def process_all_logs(target_group='knowledgebase', src_dir=os.path.join(RAW_DIR, 'train')):
    if not os.path.isfile(MAPPING):
        print("[-] No mapping found, creating new one ...")
        mapping = OrderedDict()
    else:
        print("[+] Found ready mapping, loading ...")
        with open(MAPPING) as inp:
            mapping = json.load(inp, object_pairs_hook=OrderedDict)
            print("[!] Loaded : {}".format(mapping))
    with h5py.File(KBASE_FILE, 'a') as h5file:
        kbase = h5file.create_group(target_group)
        raw_files(src_dir, fileparse(sink(kbase, mapping)))
        
    print("[!] Dumping renewed of size {} mapping back to file".format(len(mapping)))
    with open(MAPPING, 'w') as outp:
        json.dump(mapping, outp, indent=4)
    


if __name__ == '__main__':
    process_all_logs(target_group='test_samples', src_dir=RAW_DIR)
    process_all_logs()
    
    
        
