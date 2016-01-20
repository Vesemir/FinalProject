from itertools import chain


def build_scoring_matrix(alphabet, diag_score, off_diag_score, dash_score):
    return {symrow:
            {symcol: dash_score if any('-' == _ for _ in (symrow, symcol))
             else diag_score if symcol == symrow 
             else off_diag_score
             for symcol in chain(alphabet,'-')}
            for symrow in chain(alphabet, '-')}


def compute_alignment_matrix(seq_x, seq_y, scoring_matrix, global_flag):
    lenfirst, lensecond = len(seq_x), len(seq_y)
    matr = [[0 for _ in range(lensecond + 1)] for __ in range(lenfirst + 1)]
    for idx in range(1, lenfirst + 1):
        temp = matr[idx-1][0] + scoring_matrix[seq_x[idx-1]]['-']
        matr[idx][0] = temp if global_flag else 0
    for jdx in range(1, lensecond + 1):
        temp = matr[0][jdx-1] + scoring_matrix['-'][seq_y[jdx-1]]
        matr[0][jdx] = temp if global_flag else 0
    for idx in range(1, lenfirst + 1):
        for jdx in range(1, lensecond + 1):
            res = max((matr[idx-1][jdx-1] +
                                  scoring_matrix[seq_x[idx-1]][seq_y[jdx-1]]),
                                 (matr[idx-1][jdx] +
                                  scoring_matrix[seq_x[idx-1]]['-']),
                                 (matr[idx][jdx-1] +
                                  scoring_matrix['-'][seq_y[jdx-1]]))
            matr[idx][jdx] = res if global_flag else res if res >0 else 0
    return matr


def compute_local_alignment(seq_x, seq_y, scoring_matrix, alignment_matrix):
    maxpos = max(((hoel, (idx, jdx)) for idx, line in enumerate(alignment_matrix) for (jdx, hoel) in enumerate(line) ), key=lambda x: x[0])
    idx, jdx = maxpos[1]
    xslash, yslash = '', ''
    total = 0
    while idx and jdx:
        if alignment_matrix[idx][jdx] == 0:
            break
        total = max(total, alignment_matrix[idx][jdx])
        if alignment_matrix[idx][jdx] == alignment_matrix[idx-1][jdx-1] +\
           scoring_matrix[seq_x[idx-1]][seq_y[jdx-1]]:
            xslash = seq_x[idx-1] + xslash
            yslash = seq_y[jdx-1] + yslash
            idx -= 1
            jdx -= 1
        elif alignment_matrix[idx][jdx] == alignment_matrix[idx-1][jdx] +\
             scoring_matrix[seq_x[idx-1]]['-']:
            xslash = seq_x[idx-1] + xslash
            yslash = '-' + yslash
            idx -= 1
        else:
            xslash  = '-' + xslash
            yslash = seq_y[jdx-1] + yslash
            jdx -= 1
    while idx != 0:
        if alignment_matrix[idx][jdx] == 0:
            break
        xslash = seq_x[idx-1] + xslash
        yslash = '-' + yslash
        idx -= 1
    while idx != 0:
        if alignment_matrix[idx][jdx] == 0:
            break
        xslash = '-' + xslash
        yslash = seq_y[jdx-1] + yslash
        jdx -= 1
    return total, xslash, yslash
