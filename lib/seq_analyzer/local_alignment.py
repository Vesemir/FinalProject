import numpy as np
import os
import sys
import glob
import h5py

from itertools import chain, combinations, product
from collections import deque


CURDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURDIR, os.pardir))
from pander import sequence_to_list, important_functions, cached_mapping, KBASE_FILE
SEQ_LOGS = os.path.join(CURDIR, 'datas')

SCORE_MATCH = 10
SCORE_EMPTY = -6
SCORE_DIFFERENT = -2

MUTED_CALLS = [24, 25, 157, 32, 40, 23, 72, 45, 30, 49, 386]

@cached_mapping
def important_numbers(dummy, mapping=None, revmapping=None):
    imp_functions = important_functions()
    imp_numbers = [item for key, item in mapping.items() if
                   any(func in key for func in imp_functions)]
    return imp_numbers

IMPORTANT_CALLS = important_numbers(None)

def scoring_matrix(rec_1, rec_2):
    if rec_1 == rec_2:
        if rec_1 in IMPORTANT_CALLS:
            return SCORE_MATCH * 1.8
        return 0 # temporary maybe that'll work good
        if rec_1 in MUTED_CALLS:
            return 0
        
        return SCORE_MATCH
    elif rec_1 == '-' or rec_2 == '-':
        return SCORE_EMPTY
    else:
        return SCORE_DIFFERENT
    


def build_scoring_matrix(alphabet, diag_score, off_diag_score, dash_score):
    return {symrow:
            {symcol: dash_score if any('-' == _ for _ in (symrow, symcol))
             else diag_score if symcol == symrow 
             else off_diag_score
             for symcol in chain(alphabet,'-')}
            for symrow in chain(alphabet, '-')}


def compute_alignment_matrix(seq_x, seq_y, global_flag):
    lenfirst, lensecond = len(seq_x), len(seq_y)
    matr = [[0 for _ in range(lensecond + 1)] for __ in range(lenfirst + 1)]
    for idx in range(1, lenfirst + 1):
        temp = matr[idx-1][0] + scoring_matrix(seq_x[idx-1], '-')
        matr[idx][0] = temp if global_flag else 0
    for jdx in range(1, lensecond + 1):
        temp = matr[0][jdx-1] + scoring_matrix('-', seq_y[jdx-1])
        matr[0][jdx] = temp if global_flag else 0
    for idx in range(1, lenfirst + 1):
        for jdx in range(1, lensecond + 1):
            res = max((matr[idx-1][jdx-1] +
                                  scoring_matrix(seq_x[idx-1], seq_y[jdx-1])),
                                 (matr[idx-1][jdx] +
                                  scoring_matrix(seq_x[idx-1], '-')),
                                 (matr[idx][jdx-1] +
                                  scoring_matrix('-', seq_y[jdx-1])))
            matr[idx][jdx] = res if global_flag else res if res >0 else 0
    return matr


def compute_local_alignment(seq_x, seq_y, alignment_matrix):
    maxpos = max(((hoel, (idx, jdx)) for idx, line in enumerate(alignment_matrix) for (jdx, hoel) in enumerate(line) ), key=lambda x: x[0])
    idx, jdx = maxpos[1]
    xslash, yslash = deque(), deque()
    total = 0
    while idx and jdx:
        if alignment_matrix[idx][jdx] == 0:
            break
        total = max(total, alignment_matrix[idx][jdx])
        if alignment_matrix[idx][jdx] == alignment_matrix[idx-1][jdx-1] +\
           scoring_matrix(seq_x[idx-1], seq_y[jdx-1]):
            xslash.appendleft(seq_x[idx-1])
            yslash.appendleft(seq_y[jdx-1])
            idx -= 1
            jdx -= 1
        elif alignment_matrix[idx][jdx] == alignment_matrix[idx-1][jdx] +\
             scoring_matrix(seq_x[idx-1], '-'):
            xslash.appendleft(seq_x[idx-1])
            yslash.appendleft('-')
            idx -= 1
        else:
            xslash.appendleft('-')
            yslash.appendleft(seq_y[jdx-1])
            jdx -= 1
    while idx != 0:
        if alignment_matrix[idx][jdx] == 0:
            break
        xslash.appendleft(seq_x[idx-1])
        yslash.appendleft('-')
        idx -= 1
    while jdx != 0:
        if alignment_matrix[idx][jdx] == 0:
            break
        xslash.appendleft('-')
        yslash.appendleft(seq_y[jdx-1])
        jdx -= 1
    return total, xslash, yslash


def compute_alignment_helper(seq_x, seq_y, diag=10, off_diag=0, dash=-1):
    #scoring_mat = build_scoring_matrix(alphabet, diag, off_diag, dash)
    align_mat = compute_alignment_matrix(seq_x, seq_y, 0)
    return compute_local_alignment(seq_x, seq_y, align_mat)


def search_samples(seq_1, seq_2):
    print("[!] Searching {} \n {}".format(seq_1.name, seq_2.name))
    seq_1_nparray, seq_2_nparray = np.array(seq_1), np.array(seq_2)
    res = compute_alignment_helper(seq_1_nparray, seq_2_nparray)
    if res[0] >= 85:
        print("*" * 20 + "\nSCORE : {}\n\n{} :\n {}\n{} :\n {}\n".format(
            res[0], seq_1.name, sequence_to_list(res[1]),
            seq_2.name, sequence_to_list(res[2])
            )
              )    
    

def test_match():
    with h5py.File(KBASE_FILE, 'r', driver='core') as h5file:
        kbase = h5file['knowledgebase']
        samples = h5file['test_samples']
        sample_names = [each for each in samples]
        first_sample = sample_names[237]# was 37
        for sampledata, sampledata_other in product((kbase[sample] for sample in kbase), (samples[first_sample],)):
            search_samples(sampledata, sampledata_other)


if __name__ == '__main__':
    test_match()
