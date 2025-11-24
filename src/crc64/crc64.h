#ifndef CRC64_H
#define CRC64_H

// Header file created because of project necessity
// Source for c file: https://github.com/srned/baselib/blob/master/crc64.c

#include <inttypes.h>

uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l);

#endif