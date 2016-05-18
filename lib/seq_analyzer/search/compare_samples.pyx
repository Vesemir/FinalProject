import numpy as np
cimport numpy as np

DINT32 = np.int32
DFLOAT64 = np.float64


ctypedef np.int32_t DINT32_t
ctypedef np.float64_t DFLOAT64_t

cdef int SCORE_MATCH = 10
cdef int SCORE_EMPTY = -6
cdef int SCORE_DIFFERENT = -2

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
