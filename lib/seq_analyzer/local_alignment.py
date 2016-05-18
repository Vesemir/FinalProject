import numpy as np
import os
import sys
import glob
import h5py

from itertools import combinations, product
from collections import deque



import time

CURDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURDIR, os.pardir))
import scoring.scoring.compare_samples
from scoring.scoring.compare_samples import compute_alignment_matrix as align
from scoring.scoring.compare_samples import build_scoring_matrix as build_sm
from profiling import profiler
from pander import sequence_to_list, important_functions, cached_mapping, KBASE_FILE
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


def report_match(first_seq, second_seq, name1, name2, score):
    return "*" * 20 +\
          "\nSCORE : {}\n\n{} :\n {}\n{} :\n {}\n".format(
              score,
              name1,
              sequence_to_list(first_seq),
              name2,
              sequence_to_list(second_seq)
              )

    
@profiler.do_profile
def test_match():
    with h5py.File(KBASE_FILE, 'r', driver='core') as h5file:
        kbase = h5file['knowledgebase']
        samples = h5file['test_samples']
        sampless = list(samples.keys())
        #first_sample = sample_names[237]# was 37
        
        temp_time = started = time.perf_counter()
        
        scor_mat = build_sm(MAPPING_SIZE, MUTED_CALLS, IMPORTANT_CALLS)
        for idx, test_sample_name in enumerate(sampless[237:]):
            print("[!] Searching {} \n".format(test_sample_name))
            cycle_counter = 0
            sample_whole_score = 0
            similar_count = 0
            avg_cur = 0
            max_cur = 0
            score = 0
            partial_report = ''
            for trained_sample_name in kbase:
                if cycle_counter % 1000 == 0:
                    print("[!] Number {}".format(cycle_counter))
                trained_sample = kbase[trained_sample_name]
                test_sample = samples[test_sample_name]
                train, test = np.asarray(trained_sample), np.asarray(test_sample)
                size = min(map(len, (train, test)))
                found_match = search_samples(train, test,
                                             score_matrix=scor_mat)
                
                if found_match:
                    score = found_match[0]
                    first_seq, second_seq = found_match[1], found_match[2]
                    #report_match(first_seq, second_seq,
                    #             trained_sample.name, test_sample.name,
                    #             score)
                    if max_cur < score:
                        max_cur = score
                        partial_report = report_match(
                            first_seq, second_seq,
                            trained_sample.name, test_sample.name,
                            score)
                    sample_whole_score += score
                    similar_count += 1
                    avg_cur = sample_whole_score / similar_count
                    if score > 300:#5 * size:
                        print("[!] With high confidence of {} it's a virus !".format(score))
                        report = report_match(first_seq, second_seq,
                                     trained_sample.name, test_sample.name,
                                              score)
                        print(report)
                        break
                cycle_counter += 1
            else:
                print('[!] No match reaching threshold found;\nTotal average score on found sequences is {}, \n max match: {}'.format(avg_cur, partial_report))
            print("[!] Comparison took {} seconds and finished on {} comparison".format(time.perf_counter() - temp_time, cycle_counter))
            assert False, 'no'
            temp_time = time.perf_counter()
        
        print("[!] Run took {} seconds and finished on {} comparison".format(time.perf_counter() - started, cycle_counter))


if __name__ == '__main__':
    test_match()
