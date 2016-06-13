import numpy as np
import os
import sys
import glob
import h5py

from itertools import combinations, product
from collections import deque, defaultdict

import webbrowser
import time
from . import compute_alignment_matrix as align
from . import build_scoring_matrix as build_sm
from . import profiler

CURDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURDIR, os.pardir))
from . import sequence_to_list, important_functions, cached_mapping, KBASE_FILE
SEQ_LOGS = os.path.join(CURDIR, 'datas')

SCORE_MATCH = 10
SCORE_EMPTY = -6
SCORE_DIFFERENT = -2

MUTED_NAMES = [
    "kernel32.getstringtype", "kernel32.getlasterror", "kernel32.setlasterror", "kernel32.isdbcsleadbyte",
    "kernel32.regkrngetglobalstate", "kernel32.interlockedexchange", "kernel32.interlockedincrement",
    "kernel32.interlockeddecrement", "kernel32.interlockedcompareexchange",
    "kernel32.initializecriticalsectionandspincount", "kernel32.heapfree",
    "kernel32.interlockedexchangeadd"
    ]


@cached_mapping
def important_numbers(dummy, mapping=None, revmapping=None):
    imp_functions = important_functions()
    imp_numbers = np.array([item for key, item in mapping.items() if
                   any(func in key for func in imp_functions)],
                           dtype=np.int32)
    mapping_size = max(revmapping)
    muted = np.array([mapping.get(each) for each in MUTED_NAMES],
                     dtype=np.int32)
    return imp_numbers, mapping_size, muted

IMPORTANT_CALLS, MAPPING_SIZE, MUTED_CALLS = important_numbers(None)


def report_match(first_seq, second_seq, name1, name2, score, target=None):
    lb = '<BR>' if target == 'browser' else '\r\n'
    template = "*" * 20 + lb + 'SCORE : {}' + lb + '{}' +\
               ':' + lb + '{}' + lb + '{} :' + lb +' {}'
    return template.format(
              score,
              name1,
              sequence_to_list(first_seq),
              name2,
              sequence_to_list(second_seq)
              )


def build_scoring_matrix(size,
                         diag_score=SCORE_MATCH,
                         off_diag_score=SCORE_DIFFERENT,
                         dash_score=SCORE_EMPTY):
    numbers = range(size + 1)
    matr = np.zeros((size + 1, size + 1), dtype=np.int32)
    for symrow in numbers:
        for symcol in numbers:
            if not symcol or not symrow:
                matr[symrow][symcol] = dash_score
            elif symcol == symrow:
                if symcol in MUTED_CALLS:
                    matr[symrow][symcol] = 0# or 0
                elif symcol in IMPORTANT_CALLS:
                    matr[symrow][symcol] = 1.3 * diag_score
                else:
                    matr[symrow][symcol] = diag_score
            elif symcol != symrow:
                matr[symrow][symcol] = off_diag_score
    return matr


#@profiler.do_profile
def compute_alignment_matrix(seq_x, seq_y, scoring_matrix):
    lenfirst, lensecond = len(seq_x), len(seq_y)
    matr = np.zeros((lenfirst + 1, lensecond + 1))
    partial_zeros = np.zeros(lensecond)
    
    keyarray = np.arange(len(scoring_matrix))
    #[critical code], tried to optimize it as good as I can
    for idx in range(1, lenfirst + 1):
        prevrow = matr[idx-1]
        currow = matr[idx]
        score_row = scoring_matrix[seq_x[idx-1]] # bugged
        #IndexError: index 1361 is out of bounds for axis 0 with size 1361
        _idx = np.searchsorted(keyarray, seq_y)
        mapped = score_row[_idx]
        
        partial_eval = np.vstack(
            (prevrow[1:] + SCORE_EMPTY,
             prevrow[:-1] + mapped,
             partial_zeros)
            )
        maximums = partial_eval.max(axis=0)
        for jdx in range(lensecond):
            candy = maximums[jdx]
            other = currow[jdx] + SCORE_EMPTY
            if candy > other:
                currow[jdx+1] = candy
            else:
                currow[jdx+1] = other
    #[/critical code]
    return matr


def compute_local_alignment(seq_x, seq_y, scoring_matrix, alignment_matrix):
    idx, jdx = np.unravel_index(alignment_matrix.argmax(), alignment_matrix.shape)   
    xslash, yslash = deque(), deque()
    total = 0
    while idx and jdx:
        if alignment_matrix[idx][jdx] == 0:
            break
        total = max(total, alignment_matrix[idx,jdx])
        if alignment_matrix[idx,jdx] == alignment_matrix[idx-1,jdx-1] +\
           scoring_matrix[seq_x[idx-1],seq_y[jdx-1]]:
            xslash.appendleft(seq_x[idx-1])
            yslash.appendleft(seq_y[jdx-1])
            idx -= 1
            jdx -= 1
        elif alignment_matrix[idx,jdx] == alignment_matrix[idx-1,jdx] +\
             scoring_matrix[seq_x[idx-1],0]:
            xslash.appendleft(seq_x[idx-1])
            yslash.appendleft(0)
            idx -= 1
        else:
            xslash.appendleft(0)
            yslash.appendleft(seq_y[jdx-1])
            jdx -= 1
    while idx != 0:
        if alignment_matrix[idx,jdx] == 0:
            break
        xslash.appendleft(seq_x[idx-1])
        yslash.appendleft(0)
        idx -= 1
    while jdx != 0:
        if alignment_matrix[idx,jdx] == 0:
            break
        xslash.appendleft(0)
        yslash.appendleft(seq_y[jdx-1])
        jdx -= 1
    return total, xslash, yslash


def search_samples(seq_1, seq_2, score_matrix=None, size=None):
    #print("[!] Searching {} \n {}".format(seq_1.name, seq_2.name))
    align_mat = align(seq_1, seq_2, score_matrix)
    res = compute_local_alignment(seq_1, seq_2, score_matrix, align_mat)
    score = res[0]
    if score >= 85:
        return res
    return 0


def output_reports(reports, name):
    with open('report_template.txt') as inp:
        template = inp.read()
    report = template % ('Report for top %d' % len(reports), '<BR>'.join(reports))
    new = 2
    report_name = 'report_{}.html'.format(name)
    with open(report_name, 'w') as outp:
        outp.write(report)
    webbrowser.open(report_name, new=new) 


def find_slow_match(kbase, samples, scor_mat, single_match=None, TOP=3):
    reports = deque('' for _ in range(TOP))
    all_samples = list(samples.keys())
    if single_match:
        if not single_match in all_samples:
            print('[-] Specified sample %s isn\'t present in "test" database '
                  'file, terminating launch...')
            sys.exit(1)
        sample_names = [single_match]
    else:
        sample_names = all_samples
    for idx, test_sample in enumerate(sample_names):
        max_score = -10000
        avg_score = similar_num = 0
        test_seq = samples[test_sample]
        print("[!] Searching {} \n".format(test_sample))
        temp_time = time.perf_counter()
        for jdx, trained_seq in enumerate(kbase.values()):
            if jdx % 1000 == 0:
                print("[!] Compared with number {}".format(jdx))
            train, test = np.asarray(trained_seq), np.asarray(test_seq)
            found_match = search_samples(train, test,
                                         score_matrix=scor_mat)
            if found_match:
                score, first_seq, second_seq = found_match
                avg_score += score
                similar_num += 1
                if score > max_score:
                    max_score = score
                    report = report_match(first_seq, second_seq,
                                 trained_seq.name, test_seq.name,
                                          score,
                                          target='browser')
                    reports.pop()
                    reports.appendleft(report)                    
        print('[!] Total average score on found sequences is {}'.format(avg_score / similar_num))
        print("[!] Comparison took {} seconds and finished on {} comparison".format(time.perf_counter() - temp_time, jdx))
        print('[!] Opening browser, for your report and convenience!')
        output_reports(reports, test_sample)        


def trivial_heur(test_seq):
    n_unique = np.unique(test_seq).size
    if n_unique < 3:
        print('[!] Very low total number of unique calls : {}'.format(n_unique))
    if test_seq.size < 10:
        print('[!] Very short total length of call sequence: {}'.format(test_seq.size))
        

def find_fast_match(kbase, samples, scor_mat, THRESHOLD=160):
    sample_names = list(samples.keys())
    popular_kbase = defaultdict(int)
    found = nonfound = 0
    for idx, test_sample in enumerate(sample_names):
        test_seq = samples[test_sample]
        FOUND = False
        print("[!] Searching {} \n".format(test_sample))
        temp_time = time.perf_counter()
        for jdx, trained_seq in enumerate(kbase.values()):
            if jdx % 1000 == 0:
                print("[!] Number {}".format(jdx))            
            train, test = np.asarray(trained_seq), np.asarray(test_seq)
            found_match = search_samples(train, test,
                                         score_matrix=scor_mat)
            if found_match:
                score, first_seq, second_seq = found_match
                if score > THRESHOLD:
                    print("[!] With high confidence of {} it's a virus !".format(score))
                    report = report_match(first_seq, second_seq,
                                 trained_seq.name, test_seq.name,
                                          score)
                    print(report)
                    FOUND = True
                    break
        else:
            print('[!] No match reaching threshold found')
            nonfound += 1
        print("[!] Comparison took {} seconds and finished on {} comparison".format(time.perf_counter() - temp_time, jdx))
        if FOUND:
            found += 1
            popular_kbase[trained_seq.name] += 1
    print('[!] Totally found {} and non found {} samples'.format(found, nonfound))
    print(popular_kbase)

            
#@profiler.do_profile
def test_match(strategy='SLOW', match_one=None, test_group='test_samples'):
    with h5py.File(KBASE_FILE, 'r', driver='core') as h5file:
        present_groups = list(kbase.keys())
        for each in ('knowledgebase', test_group):
            if each not in present_groups:
                print('[-] %s group isn\'t present in knowledgebase file!')
                sys.exit(1)
        kbase = h5file['knowledgebase']
        samples = h5file[test_group]
        scor_mat = build_sm(MAPPING_SIZE, MUTED_CALLS, IMPORTANT_CALLS)
                        
        started = time.perf_counter()
        if strategy == 'SLOW':
            find_slow_match(kbase, samples, scor_mat,
                            single_match=match_one,
                            TOP=10)
        elif strategy == 'FAST':
            find_fast_match(kbase, samples, scor_mat)        
        
        print("[!] Run took {} seconds".format(time.perf_counter() - started))


if __name__ == '__main__':
    test_match('SLOW', match_one='f2d89c29fdcf0a3509350c3751564b5d')
