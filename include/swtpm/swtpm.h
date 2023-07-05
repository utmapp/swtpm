/*
 * swtpm.h
 *
 * (c) Copyright IBM Corporation 2023.
 *
 * This file is licensed under the terms of the 3-clause BSD license
 */
#ifndef _SWTPM_H_
#define _SWTPM_H_

#include <stdint.h>
#include <libtpms/tpm_library.h>

struct swtpm_options {
    int sizeOfStruct;
    TPMLIB_TPMVersion tpmversion;
    const char *key;
    const char *migkey;
    const char *log;
    const char *pid;
    const char *locality;
    const char *tpmstate;
    const char *ctrlch;
    const char *server;
    const char *flags;
    const char *seccomp;
    const char *migration;
};

int swtpm_start(struct swtpm_options *options);
void swtpm_stop(void);

#endif /* _SWTPM_H_ */
