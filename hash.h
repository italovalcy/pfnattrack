#ifndef _JENKINS_HASH_H_
#define _JENKINS_HASH_H_
#include <sys/types.h>

/*
 * * Hashing function from Bob Jenkins. Implementation from freebsd kernel in
 * libkern/jenkins_hash.c.
 **/
uint32_t jenkins_hash32(const uint32_t *, size_t, uint32_t);

#endif
