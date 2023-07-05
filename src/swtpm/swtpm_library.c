/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                 Written by Ken Goldman, Stefan Berger                        */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2016, 2019.			*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>
#include <swtpm/swtpm.h>

#include "main.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "swtpm_nvstore.h"
#include "server.h"
#include "common.h"
#include "logging.h"
#include "pidfile.h"
#include "tpmlib.h"
#include "utils.h"
#include "mainloop.h"
#include "ctrlchannel.h"
#include "tpmstate.h"
#include "sys_dependencies.h"
#include "seccomp_profile.h"
#include "options.h"

/* local variables */
static int notify_fd[2] = {-1, -1};

static struct libtpms_callbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init          = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata     = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = SWTPM_IO_Init,
    .tpm_io_getlocality      = mainloop_cb_get_locality,
};

void swtpm_stop(void)
{
    TPM_DEBUG("Terminating...\n");
    if (write(notify_fd[1], "T", 1) < 0) {
        logprintf(STDERR_FILENO, "Error: sigterm notification failed: %s\n",
                  strerror(errno));
    }
    mainloop_terminate = true;
}

static void swtpm_cleanup(struct ctrlchannel *cc, struct server *server)
{
    pidfile_remove();
    ctrlchannel_free(cc);
    server_free(server);
    log_global_free();
    tpmstate_global_free();
    SWTPM_NVRAM_Shutdown();
}

int swtpm_start(struct swtpm_options *options)
{
    TPM_RESULT rc = 0;
    struct mainLoopParams mlp = {
        .cc = NULL,
        .flags = 0,
        .fd = -1,
        .locality_flags = 0,
        .tpmversion = TPMLIB_TPM_VERSION_1_2,
        .startupType = _TPM_ST_NONE,
        .lastCommand = TPM_ORDINAL_NONE,
        .disable_auto_shutdown = false,
        .incoming_migration = false,
        .storage_locked = false,
    };
    struct server *server = NULL;
    bool need_init_cmd = true;
#ifdef DEBUG
    time_t              start_time;
#endif
    unsigned int seccomp_action;

    if (!options || options->sizeOfStruct != sizeof(*options)) {
        return EXIT_FAILURE;
    }
    mlp.tpmversion = options->tpmversion;

    log_set_prefix("swtpm: ");

    if (handle_log_options(options->log) < 0)
        return EXIT_FAILURE;

    if (tpmlib_choose_tpm_version(mlp.tpmversion) != TPM_SUCCESS)
        return EXIT_FAILURE;

    if (handle_ctrlchannel_options(options->ctrlch, &mlp.cc, &mlp.flags) < 0 ||
        handle_server_options(options->server, &server) < 0) {
        goto exit_failure;
    }

    tpmstate_set_version(mlp.tpmversion);

    if (handle_key_options(options->key) < 0 ||
        handle_migration_key_options(options->migkey) < 0 ||
        handle_pid_options(options->pid) < 0 ||
        handle_locality_options(options->locality, &mlp.locality_flags) < 0 ||
        handle_tpmstate_options(options->tpmstate) < 0 ||
        handle_seccomp_options(options->seccomp, &seccomp_action) < 0 ||
        handle_flags_options(options->flags, &need_init_cmd,
                             &mlp.startupType, &mlp.disable_auto_shutdown) < 0 ||
        handle_migration_options(options->migration, &mlp.incoming_migration,
                                 &mlp.release_lock_outgoing) < 0) {
        goto exit_failure;
    }

    if (server) {
        if (server_get_fd(server) >= 0) {
            mlp.fd = server_set_fd(server, -1);
            SWTPM_IO_SetSocketFD(mlp.fd);
        }

        mlp.flags |= MAIN_LOOP_FLAG_KEEP_CONNECTION;
        if ((server_get_flags(server) & SERVER_FLAG_DISCONNECT))
            mlp.flags &= ~MAIN_LOOP_FLAG_KEEP_CONNECTION;

        if ((server_get_flags(server) & SERVER_FLAG_FD_GIVEN))
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
    }

    if (pidfile_write(getpid()) < 0) {
        goto exit_failure;
    }

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe */

#ifdef DEBUG
    /* initialization */
    start_time = time(NULL);
#endif

    TPM_DEBUG("main: Initializing TPM at %s", ctime(&start_time));

    tpmlib_debug_libtpms_parameters(mlp.tpmversion);

    if ((rc = tpmlib_register_callbacks(&callbacks)))
        goto error_no_tpm;

    if (!need_init_cmd) {
        mlp.storage_locked = !mlp.incoming_migration;

        if ((rc = tpmlib_start(0, mlp.tpmversion, mlp.storage_locked)))
            goto error_no_tpm;
        tpm_running = true;
    }

    if (pipe(notify_fd) < 0)
        goto error_no_pipe;

    if (create_seccomp_profile(false, seccomp_action) < 0)
        goto error_seccomp_profile;

    rc = mainLoop(&mlp, notify_fd[0]);

error_seccomp_profile:
    uninstall_sighandlers();

error_no_pipe:
    TPMLIB_Terminate();

error_no_tpm:
    close(notify_fd[0]);
    notify_fd[0] = -1;
    close(notify_fd[1]);
    notify_fd[1] = -1;

    swtpm_cleanup(mlp.cc, server);

    /* Fatal initialization errors cause the program to abort */
    if (rc == 0) {
        return EXIT_SUCCESS;
    }
    else {
        TPM_DEBUG("main: TPM initialization failure %08x, exiting\n", rc);
        return EXIT_FAILURE;
    }

exit_failure:
    swtpm_cleanup(mlp.cc, server);

    return EXIT_FAILURE;
}
