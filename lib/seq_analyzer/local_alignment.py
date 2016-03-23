import numpy as np
import os
import sys
import glob

from itertools import chain, combinations
from collections import deque



CURDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURDIR, os.pardir))
from pander import sequence_to_list
SEQ_LOGS = os.path.join(CURDIR, 'datas')

SCORE_MATCH = 10
SCORE_EMPTY = -1
SCORE_DIFFERENT = 0

def scoring_matrix(rec_1, rec_2):
    return SCORE_MATCH if rec_1 == rec_2 else SCORE_EMPTY\
           if rec_1 == '-' or rec_2 == '-'\
           else SCORE_DIFFERENT


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


def search_samples(name_1, name_2):
    seq_1 = np.load(name_1)
    seq_2 = np.load(name_2)
    #print("[!] Searching {} \n {}".format(seq_1, seq_2))
    res = compute_alignment_helper(seq_1, seq_2)
    if res[0] >= 85:
        print("*" * 20 + "\nSCORE : {}\n\n{} :\n {}\n{} :\n {}\n".format(
            res[0], os.path.basename(name_1), sequence_to_list(res[1]),
            os.path.basename(name_2), sequence_to_list(res[2])
            )
              )
    

def test_match():
    for fil, otherfil in combinations(glob.glob(os.path.join(SEQ_LOGS, '*')), 2):
        if fil != otherfil:
            search_samples(fil, otherfil)

