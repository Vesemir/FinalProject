import numpy as np
cimport numpy as np
cimport cython

DINT32 = np.int32
DFLOAT64 = np.float64


ctypedef np.int32_t DINT32_t
ctypedef np.float64_t DFLOAT64_t

cdef int SCORE_MATCH = 10
cdef int SCORE_MATCH_IMPORTANT = 13
cdef int SCORE_EMPTY = -6
cdef int SCORE_DIFFERENT = -2


def build_scoring_matrix(int size,
                         np.ndarray[DINT32_t, ndim=1] MUTED_CALLS,
                         np.ndarray[DINT32_t, ndim=1] IMPORTANT_CALLS):
    cdef int diag_score = SCORE_MATCH
    cdef int off_diag_score = SCORE_DIFFERENT
    cdef int dash_score = SCORE_EMPTY
    cdef int diag_important_score = SCORE_MATCH_IMPORTANT
    cdef int symrow, symcol
    cdef np.ndarray[DINT32_t, ndim=2] matr = np.zeros(
        (size + 1, size + 1), dtype=DINT32)
    for symrow in range(size + 1):
        for symcol in range(size + 1):
            if not symcol or not symrow:
                if symcol in MUTED_CALLS or symrow in MUTED_CALLS:
                    matr[symrow,symcol] = 0
                else:
                    matr[symrow,symcol] = dash_score
            elif symcol == symrow:
                if symcol in MUTED_CALLS:
                    matr[symrow,symcol] = 0# or 0
                elif symcol in IMPORTANT_CALLS:
                    matr[symrow,symcol] = diag_important_score
                else:
                    matr[symrow,symcol] = diag_score
            elif symcol != symrow:
                matr[symrow,symcol] = off_diag_score
    return matr

@cython.boundscheck(False)
@cython.wraparound(False)
def compute_alignment_matrix(np.ndarray[DINT32_t, ndim=1] seq_x,
                             np.ndarray[DINT32_t, ndim=1] seq_y,
                             np.ndarray[DINT32_t, ndim=2] scoring_matrix):
    cdef int lenfirst = len(seq_x)
    cdef int lensecond = len(seq_y)
    cdef np.ndarray[DINT32_t, ndim=2] matr = np.zeros(
        (lenfirst + 1, lensecond + 1),
        dtype=DINT32
        )
    cdef int idx, jdx
    #[critical code], tried to optimize it as good as I can
    for idx in range(1, lenfirst + 1):
        for jdx in range(1, lensecond + 1):
            matr[idx, jdx] = max(
                matr[idx-1, jdx] + SCORE_EMPTY,
                matr[idx-1, jdx-1] + scoring_matrix[seq_x[idx-1], seq_y[jdx-1]],
                matr[idx, jdx-1] + SCORE_EMPTY,                
                0
                )            
    #[/critical code]
    return matr
