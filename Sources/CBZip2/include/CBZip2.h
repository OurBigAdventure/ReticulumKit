#ifndef CBZip2_h
#define CBZip2_h

#include <stddef.h>

/// Compress `sourceLen` bytes at `source` with bzip2 (Python `bz2.compress` level 9).
///
/// On entry `destLen` is the capacity of `dest`. On success it is the compressed size.
/// Returns 0 on success, non-zero on failure (including insufficient `dest` capacity).
int cbzip2_compress(
    const void *source,
    unsigned int sourceLen,
    void *dest,
    unsigned int *destLen
);

/// Decompress `sourceLen` bytes at `source`.
///
/// On entry `destLen` is the capacity of `dest` (maximum allowed uncompressed size).
/// On success it is the uncompressed size. Returns 0 on success, non-zero on failure.
int cbzip2_decompress(
    const void *source,
    unsigned int sourceLen,
    void *dest,
    unsigned int *destLen
);

#endif
