#include "CBZip2.h"
#include <bzlib.h>

int cbzip2_compress(
    const void *source,
    unsigned int sourceLen,
    void *dest,
    unsigned int *destLen
) {
    if (source == NULL || dest == NULL || destLen == NULL) {
        return -1;
    }
    return BZ2_bzBuffToBuffCompress(
        dest,
        destLen,
        (char *)source,
        sourceLen,
        9,
        0,
        30
    );
}

int cbzip2_decompress(
    const void *source,
    unsigned int sourceLen,
    void *dest,
    unsigned int *destLen
) {
    if (source == NULL || dest == NULL || destLen == NULL) {
        return -1;
    }
    return BZ2_bzBuffToBuffDecompress(
        dest,
        destLen,
        (char *)source,
        sourceLen,
        0,
        0
    );
}
