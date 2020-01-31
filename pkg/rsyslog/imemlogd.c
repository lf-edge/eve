/* imemlogd.c
 * This is the implementation of the Unix sockets input module.
 *
 * NOTE: read comments in module-template.h to understand how this file
 *       works!
 *
 * File begun on 2007-12-20 by RGerhards (extracted from syslogd.c)
 *
 * Copyright 2007-2019 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */
#ifdef __sun
#define _XPG4_2
#endif
#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "rsyslog.h"
#include "dirty.h"
#include "cfsysline.h"
#include "unicode-helper.h"
#include "module-template.h"
#include "srUtils.h"
#include "errmsg.h"
#include "net.h"
#include "glbl.h"
#include "msg.h"
#include "parser.h"
#include "prop.h"
#include "debug.h"
#include "ruleset.h"
#include "unlimited_select.h"
#include "datetime.h"
#include "hashtable.h"
#include "ratelimit.h"


MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("imemlogd")

/* defines */
#ifndef _PATH_LOG
#ifdef BSD
#define _PATH_LOG   "/var/run/log"
#else
#define _PATH_LOG   "/dev/log"
#endif
#endif
#ifndef SYSTEMD_JOURNAL
#define SYSTEMD_JOURNAL  "/run/systemd/journal"
#endif
#ifndef SYSTEMD_PATH_LOG
#define SYSTEMD_PATH_LOG SYSTEMD_JOURNAL "/syslog"
#endif
#define UNSET -1 /* to indicate a value has not been configured */

/* forward definitions */
static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal);

#if defined(_AIX)
#define ucred  ucred_t
#endif
/* emulate struct ucred for platforms that do not have it */
#ifndef HAVE_SCM_CREDENTIALS
struct ucred { int pid; uid_t uid; gid_t gid; };
#endif

/* handle some defines missing on more than one platform */
#ifndef SUN_LEN
#define SUN_LEN(su) \
    (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif
/* Module static data */
DEF_IMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(prop)
DEFobjCurrIf(net)
DEFobjCurrIf(parser)
DEFobjCurrIf(datetime)
DEFobjCurrIf(ruleset)


statsobj_t *modStats;
STATSCOUNTER_DEF(ctrSubmit, mutCtrSubmit)
STATSCOUNTER_DEF(ctrLostRatelimit, mutCtrLostRatelimit)
STATSCOUNTER_DEF(ctrNumRatelimiters, mutCtrNumRatelimiters)


/* a very simple "hash function" for process IDs - we simply use the
 * pid itself: it is quite expected that all pids may log some time, but
 * from a collision point of view it is likely that long-running daemons
 * start early and so will stay right in the top spots of the
 * collision list.
 */
static unsigned int
hash_from_key_fn(void *k)
{
    return((unsigned) *((pid_t*) k));
}

static int
key_equals_fn(void *key1, void *key2)
{
    return *((pid_t*) key1) == *((pid_t*) key2);
}


/* structure to describe a specific listener */
typedef struct lstn_s {
    uchar *sockName;    /* read-only after startup */
    prop_t *hostName;   /* host-name override - if set, use this instead of actual name */
    int fd;         /* read-only after startup */
    int flags;      /* should parser parse host name?  read-only after startup */
    int flowCtl;        /* flow control settings for this socket */
    unsigned int ratelimitInterval;
    unsigned int ratelimitBurst;
    ratelimit_t *dflt_ratelimiter;/*ratelimiter to apply if none else is to be used */
    intTiny ratelimitSev;   /* severity level (and below) for which rate-limiting shall apply */
    struct hashtable *ht;   /* our hashtable for rate-limiting */
    sbool bDiscardOwnMsgs;  /* discard messages that originated from ourselves */
    sbool bUnlink;      /* unlink&re-create socket at start and end of processing */
} lstn_t;
static lstn_t *listeners;

static prop_t *pLocalHostIP = NULL; /* there is only one global IP for all internally-generated messages */
static prop_t *pInputName = NULL;   /* our inputName currently is always "imemlogd", and this will hold it */
static int startIndexUxLocalSockets; /* process fd from that index on (used to
                * suppress local logging. rgerhards 2005-08-01
                * read-only after startup
                */
static int nfd = 1; /* number of active unix sockets  (socket 0 is always reserved for the system
            socket, even if it is not enabled. */

#if (defined(__FreeBSD__) && (__FreeBSD_version >= 1200061))
    #define DFLT_bUseSpecialParser 0
#else
    #define DFLT_bUseSpecialParser 1
#endif
#define DFLT_bCreatePath 0
#define DFLT_ratelimitInterval 0
#define DFLT_ratelimitBurst 200
#define DFLT_ratelimitSeverity 1            /* do not rate-limit emergency messages */

/* config vars for the v2 config system (rsyslog v6+) */
struct instanceConf_s {
    uchar *sockName;
    uchar *pLogHostName;        /* host name to use with this socket */
    unsigned int ratelimitInterval;     /* interval in seconds, 0 = off */
    unsigned int ratelimitBurst;        /* max nbr of messages in interval */
    int ratelimitSeverity;
    sbool bDiscardOwnMsgs;      /* discard messages that originated from our own pid? */
    sbool bUnlink;
    uchar *pszBindRuleset;      /* name of ruleset to bind to */
    ruleset_t *pBindRuleset;
    struct instanceConf_s *next;
};

struct modConfData_s {
    rsconf_t *pConf;        /* our overall config object */
    instanceConf_t *root, *tail;
    uchar *pLogSockName;
    unsigned int ratelimitIntervalSysSock;
    unsigned int ratelimitBurstSysSock;
    int ratelimitSeveritySysSock;
    sbool bDiscardOwnMsgs;
    sbool configSetViaV2Method;
    sbool bUnlink;
};
static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current load process */

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
    { "syssock.use", eCmdHdlrBinary, 0 },
    { "syssock.name", eCmdHdlrGetWord, 0 },
    { "syssock.unlink", eCmdHdlrBinary, 0 }
};
static struct cnfparamblk modpblk =
    { CNFPARAMBLK_VERSION,
      sizeof(modpdescr)/sizeof(struct cnfparamdescr),
      modpdescr
    };

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
    { "socket", eCmdHdlrString, CNFPARAM_REQUIRED },
    { "unlink", eCmdHdlrBinary, 0 }
};
static struct cnfparamblk inppblk =
    { CNFPARAMBLK_VERSION,
      sizeof(inppdescr)/sizeof(struct cnfparamdescr),
      inppdescr
    };

#include "im-helper.h" /* must be included AFTER the type definitions! */


/* create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
    instanceConf_t *inst;
    DEFiRet;
    CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
    inst->sockName = NULL;
    inst->pszBindRuleset = NULL;
    inst->ratelimitInterval = DFLT_ratelimitInterval;
    inst->ratelimitBurst = DFLT_ratelimitBurst;
    inst->ratelimitSeverity = DFLT_ratelimitSeverity;
    inst->bDiscardOwnMsgs = bProcessInternalMessages;
    inst->bUnlink = 1;
    inst->next = NULL;

    /* node created, let's add to config */
    if(loadModConf->tail == NULL) {
        loadModConf->tail = loadModConf->root = inst;
    } else {
        loadModConf->tail->next = inst;
        loadModConf->tail = inst;
    }

    *pinst = inst;
finalize_it:
    RETiRet;
}


/* This function is called when a new listen socket instance shall be added to
 * the current config object via the legacy config system. It just shuffles
 * all parameters to the listener in-memory instance.
 * rgerhards, 2011-05-12
 */
static rsRetVal addInstance(void __attribute__((unused)) *pVal, uchar *pNewVal)
{
    instanceConf_t *inst;
    DEFiRet;

    if(pNewVal == NULL || pNewVal[0] == '\0') {
        LogError(0, RS_RET_SOCKNAME_MISSING , "imemlogd: socket name must be specified, "
                    "but is not - listener not created\n");
        if(pNewVal != NULL)
            free(pNewVal);
        ABORT_FINALIZE(RS_RET_SOCKNAME_MISSING);
    }

    CHKiRet(createInstance(&inst));
    inst->sockName = pNewVal;
    inst->next = NULL;

finalize_it:
    RETiRet;
}


/* add an additional listen socket.
 * added capability to specify hostname for socket -- rgerhards, 2008-08-01
 */
static rsRetVal
addListner(instanceConf_t *inst)
{
    DEFiRet;

    if(inst->pLogHostName == NULL) {
        listeners[nfd].hostName = NULL;
    } else {
        CHKiRet(prop.Construct(&(listeners[nfd].hostName)));
        CHKiRet(prop.SetString(listeners[nfd].hostName, inst->pLogHostName, ustrlen(inst->pLogHostName)));
        CHKiRet(prop.ConstructFinalize(listeners[nfd].hostName));
    }
    if(inst->ratelimitInterval > 0) {
        if((listeners[nfd].ht = create_hashtable(100, hash_from_key_fn, key_equals_fn,
            (void(*)(void*))ratelimitDestruct)) == NULL) {
            /* in this case, we simply turn off rate-limiting */
            DBGPRINTF("imemlogd: turning off rate limiting because we could not "
                  "create hash table\n");
            inst->ratelimitInterval = 0;
        }
    } else {
        listeners[nfd].ht = NULL;
    }
    listeners[nfd].ratelimitInterval = inst->ratelimitInterval;
    listeners[nfd].ratelimitBurst = inst->ratelimitBurst;
    listeners[nfd].ratelimitSev = inst->ratelimitSeverity;
    listeners[nfd].sockName = ustrdup(inst->sockName);
    listeners[nfd].bDiscardOwnMsgs = inst->bDiscardOwnMsgs;
    listeners[nfd].bUnlink = inst->bUnlink;
    CHKiRet(ratelimitNew(&listeners[nfd].dflt_ratelimiter, "imemlogd", NULL));
    ratelimitSetLinuxLike(listeners[nfd].dflt_ratelimiter,
                  listeners[nfd].ratelimitInterval,
                  listeners[nfd].ratelimitBurst);
    ratelimitSetSeverity(listeners[nfd].dflt_ratelimiter,
                 listeners[nfd].ratelimitSev);
    nfd++;

finalize_it:
    RETiRet;
}


static rsRetVal discardLogSockets(void)
{
    int i;

    /* Check whether the system socket is in use */
    if(startIndexUxLocalSockets == 0) {
        /* Clean up rate limiting data for the system socket */
        if(listeners[0].ht != NULL) {
            hashtable_destroy(listeners[0].ht, 1); /* 1 => free all values automatically */
        }
        ratelimitDestruct(listeners[0].dflt_ratelimiter);
    }

    /* Clean up all other sockets */
    for (i = 1; i < nfd; i++) {
        if(listeners[i].sockName != NULL) {
            free(listeners[i].sockName);
            listeners[i].sockName = NULL;
        }
        if(listeners[i].hostName != NULL) {
            prop.Destruct(&(listeners[i].hostName));
        }
        if(listeners[i].ht != NULL) {
            hashtable_destroy(listeners[i].ht, 1); /* 1 => free all values automatically */
        }
        ratelimitDestruct(listeners[i].dflt_ratelimiter);
    }

    return RS_RET_OK;
}


/* used to create a log socket if NOT passed in via systemd.
 */
/* note: the linux SUN_LEN macro uses a sizeof based on a NULL pointer. This
 * triggers UBSan warning. As such, we turn that warning off for the fuction.
 * As it is OS-provided, there is no way to solve it ourselves. The problem
 * may also exist on other platforms, we have just noticed it on Linux.
 */
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Wunknown-attributes"
#endif
static rsRetVal
#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
createLogSocket(lstn_t *pLstn)
{
    struct sockaddr_un sunx;
    DEFiRet;

    if(pLstn->bUnlink)
        unlink((char*)pLstn->sockName);
    memset(&sunx, 0, sizeof(sunx));
    sunx.sun_family = AF_UNIX;
    strncpy(sunx.sun_path, (char*)pLstn->sockName, sizeof(sunx.sun_path));
    sunx.sun_path[sizeof(sunx.sun_path)-1] = '\0';
    pLstn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(pLstn->fd < 0 ) {
        ABORT_FINALIZE(RS_RET_ERR_CRE_AFUX);
    }
    if(connect(pLstn->fd, (struct sockaddr *) &sunx, SUN_LEN(&sunx)) < 0) {
        LogError(errno, iRet, "XXXXX cannot create '%s'\n", pLstn->sockName);
        ABORT_FINALIZE(RS_RET_ERR_CRE_AFUX);
    }
    LogError(errno, NO_ERRCODE, "##### Connected to socket: %s\n",
            pLstn->sockName);
    if(chmod((char*)pLstn->sockName, 0666) < 0) {
        ABORT_FINALIZE(RS_RET_ERR_CRE_AFUX);
    }
    char dump_buf[1];
    dump_buf[0] = 2;
    if (write(pLstn->fd, dump_buf, 1) != 1) {
        LogError(errno, NO_ERRCODE, "XXXXX Unable to write the dump mode");
    }
finalize_it:
    if(iRet != RS_RET_OK) {
        LogError(errno, iRet, "cannot create '%s'", pLstn->sockName);
        if(pLstn->fd != -1) {
            close(pLstn->fd);
            pLstn->fd = -1;
        }
    }
    RETiRet;
}


static rsRetVal
openLogSocket(lstn_t *pLstn)
{
    DEFiRet;

    if(pLstn->sockName[0] == '\0')
        return -1;

    pLstn->fd = -1;

    if (pLstn->fd == -1) {
        CHKiRet(createLogSocket(pLstn));
        assert(pLstn->fd != -1); /* else createLogSocket() should have failed! */
    }

finalize_it:
    if(iRet != RS_RET_OK) {
        if(pLstn->fd != -1) {
            close(pLstn->fd);
            pLstn->fd = -1;
        }
    }

    RETiRet;
}


/* find ratelimiter to use for this message. Currently, we use the
 * pid, but may change to cgroup later (probably via a config switch).
 * Returns NULL if not found or rate-limiting not activated for this
 * listener (the latter being a performance enhancement).
 */
static rsRetVal
findRatelimiter(lstn_t *pLstn, struct ucred *cred, ratelimit_t **prl)
{
    ratelimit_t *rl = NULL;
    int r;
    pid_t *keybuf;
    char pinfobuf[512];
    DEFiRet;

    if(cred == NULL)
        FINALIZE;
    if(pLstn->ht == NULL) {
        *prl = NULL;
        FINALIZE;
    }

    rl = hashtable_search(pLstn->ht, &cred->pid);
    if(rl == NULL) {
        /* we need to add a new ratelimiter, process not seen before! */
        DBGPRINTF("imemlogd: no ratelimiter for pid %lu, creating one\n",
              (unsigned long) cred->pid);
        STATSCOUNTER_INC(ctrNumRatelimiters, mutCtrNumRatelimiters);
        /* read process name from system  */
        char procName[256]; /* enough for any sane process name  */
        snprintf(procName, sizeof(procName), "/proc/%lu/cmdline", (unsigned long) cred->pid);
        FILE *f = fopen(procName, "r");
        if (f) {
            size_t len;
            len = fread(procName, sizeof(char), 256, f);
            if (len > 0) {
                snprintf(pinfobuf, sizeof(pinfobuf), "pid: %lu, name: %s",
                    (unsigned long) cred->pid, procName);
            }
            fclose(f);
        }
        else {
            snprintf(pinfobuf, sizeof(pinfobuf), "pid: %lu",
                (unsigned long) cred->pid);
        }
        pinfobuf[sizeof(pinfobuf)-1] = '\0'; /* to be on safe side */
        CHKiRet(ratelimitNew(&rl, "imemlogd", pinfobuf));
        ratelimitSetLinuxLike(rl, pLstn->ratelimitInterval, pLstn->ratelimitBurst);
        ratelimitSetSeverity(rl, pLstn->ratelimitSev);
        CHKmalloc(keybuf = malloc(sizeof(pid_t)));
        *keybuf = cred->pid;
        r = hashtable_insert(pLstn->ht, keybuf, rl);
        if(r == 0)
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    *prl = rl;
    rl = NULL;

finalize_it:
    if(rl != NULL)
        ratelimitDestruct(rl);
    if(*prl == NULL)
        *prl = pLstn->dflt_ratelimiter;
    RETiRet;
}

char *parseSourceName(uchar *msg, int msgLen)
{
    int i, source_len;
    bool found_colon = false;
    int source_start = 0;
    char *source_name = NULL;

    for (i = 0; i < msgLen; i++) {
        if (msg[i] == ';') {
            found_colon = true;
            break;
        }
    }
    if (found_colon && i > 0) {
        source_start = i - 1;
        while (source_start >= 0 && msg[source_start] != ',') {
            source_start--;
        }
        if (source_start < 0) {
            return source_name;
        }
        source_len = i - source_start - 1;
        source_name = (char *) malloc(sizeof(char) * (source_len + 1));
        if (source_name == NULL) {
            return source_name;
        }
        memcpy(source_name, &msg[source_start + 1], source_len);
        source_name[source_len] = '\0';
    }
    return source_name;
}

/* submit received message to the queue engine
 * We now parse the message according to expected format so that we
 * can also mangle it if necessary.
 */
static rsRetVal
SubmitMsg(uchar *pRcv, int lenRcv, lstn_t *pLstn, struct ucred *cred, struct timeval *ts)
{
    smsg_t *pMsg = NULL;
    int lenMsg;
    int offs;
    int i;
    uchar *parse;
    syslog_pri_t pri;
    uchar bufParseTAG[CONF_TAG_MAXSIZE];
    struct syslogTime st;
    time_t tt;
    ratelimit_t *ratelimiter = NULL;
    struct syslogTime dummyTS;
    DEFiRet;

    char *source_name = parseSourceName(pRcv, lenRcv);
    if (source_name == NULL) {
        RETiRet;
    }
    // Find the first semi-colon
    int colon_index, json_start = 0;
    for (colon_index = 0; colon_index < lenRcv; colon_index++) {
        if (pRcv[colon_index] == ';') {
            if (pRcv[colon_index + 1] == '{' && colon_index >= 10) {
                json_start = colon_index + 1;
                pRcv[colon_index] = ':';
            }
        }
    }
    if (json_start > 0) {
        pRcv = &pRcv[json_start];
        lenRcv = lenRcv - json_start + 1;
    }
    if(pLstn->bDiscardOwnMsgs && cred != NULL && cred->pid == glblGetOurPid()) {
        DBGPRINTF("imemlogd: discarding message from our own pid\n");
        FINALIZE;
    }

    findRatelimiter(pLstn, cred, &ratelimiter); /* ignore error, better so than others... */

    if(ts == NULL) {
        datetime.getCurrTime(&st, &tt, TIME_IN_LOCALTIME);
    } else {
        datetime.timeval2syslogTime(ts, &st, TIME_IN_LOCALTIME);
        tt = ts->tv_sec;
    }

    /* we now create our own message object and submit it to the queue */
    CHKiRet(msgConstructWithTime(&pMsg, &st, tt));

    MsgSetFlowControlType(pMsg, eFLOWCTL_LIGHT_DELAY);
    MsgSetInputName(pMsg, pInputName);
    MsgSetRawMsgWOSize(pMsg, (char*)pRcv);
    MsgSetMSGoffs(pMsg, 0); /* we do not have a header... */
    MsgSetHOSTNAME(pMsg, glbl.GetLocalHostName(), ustrlen(glbl.GetLocalHostName()));
    MsgSetTAG(pMsg, (uchar *) source_name, ustrlen((char *) source_name));
    msgSetPRI(pMsg, pri);

    MsgSetRcvFrom(pMsg, pLstn->hostName == NULL ? glbl.GetLocalHostNameProp() : pLstn->hostName);
    CHKiRet(MsgSetRcvFromIP(pMsg, pLocalHostIP));
    ratelimitAddMsg(ratelimiter, NULL, pMsg);
    STATSCOUNTER_INC(ctrSubmit, mutCtrSubmit);
finalize_it:
    if (source_name != NULL) {
        free(source_name);
    }
    if(iRet != RS_RET_OK) {
        if(pMsg != NULL)
            msgDestruct(&pMsg);
    }
    RETiRet;
}


/* This function receives data from a socket indicated to be ready
 * to receive and submits the message received for processing.
 * rgerhards, 2007-12-20
 * Interface changed so that this function is passed the array index
 * of the socket which is to be processed. This eases access to the
 * growing number of properties. -- rgerhards, 2008-08-01
 */
static rsRetVal readSocket(lstn_t *pLstn)
{
    DEFiRet;
    int iRcvd;
    int iMaxLine, len = 0;
    struct ucred cred;
    int cred_set = 0;
    uchar *pRcv = NULL; /* receive buffer */
    uchar *p, *q;

    assert(pLstn->fd >= 0);

    iMaxLine = glbl.GetMaxLine();

    iMaxLine = 32768;
    CHKmalloc(pRcv = (uchar*) malloc(iMaxLine + 1));

    while (1) {
        DBGPRINTF("--------imemlogd calling recv() on %d fds\n", nfd);

        if(glbl.GetGlobalInputTermState() == 1)
            break; /* terminate input! */

        if(glbl.GetGlobalInputTermState() == 1)
            ABORT_FINALIZE(RS_RET_FORCE_TERM); /* terminate input! */

        iRcvd = recv(pLstn->fd, pRcv + len, iMaxLine - len, 0);

        DBGPRINTF("Message from UNIX socket: #%d, size %d\n", pLstn->fd, (int) iRcvd);
        if(iRcvd > 0) {
            pRcv[iRcvd + len] = '\0';
        } else if(iRcvd < 0 && errno != EINTR && errno != EAGAIN) {
            char errStr[1024];
            rs_strerror_r(errno, errStr, sizeof(errStr));
            DBGPRINTF("UNIX socket error: %d = %s.\n", errno, errStr);
            LogError(errno, NO_ERRCODE, "imemlogd: recvfrom UNIX");
        }
        for (p = (char*)pRcv; (q = strchr(p, '\n')) != NULL; p = q + 1) {
            *q = '\0';
            CHKiRet(SubmitMsg(p, strlen(p), pLstn, (cred_set ? &cred : NULL), NULL));
        }
        len = strlen(p);
        if (len >= iMaxLine - 1) {
            CHKiRet(SubmitMsg(p, strlen(p), pLstn, (cred_set ? &cred : NULL), NULL));
            len = 0;
        }
        if (len > 0) {
            memmove(pRcv, p, len + 1);
        }

    }

finalize_it:
    if(pRcv != NULL)
        free(pRcv);

    RETiRet;
}


/* activate current listeners */
static rsRetVal
activateListeners(void)
{
    int actSocks;
    int i;
    DEFiRet;

    /* initialize and return if will run or not */
    actSocks = 0;
    for (i = startIndexUxLocalSockets ; i < nfd ; i++) {
        if(openLogSocket(&(listeners[i])) == RS_RET_OK) {
            ++actSocks;
            DBGPRINTF("imemlogd: Opened UNIX socket '%s' (fd %d).\n",
                  listeners[i].sockName, listeners[i].fd);
        }
    }

    if(actSocks == 0) {
        LogError(0, RS_RET_ERR, "imemlogd does not run because we could not "
            "aquire any socket\n");
        ABORT_FINALIZE(RS_RET_ERR);
    }

finalize_it:
    RETiRet;
}



BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
    loadModConf = pModConf;
    pModConf->pConf = pConf;
    /* init our settings */
    pModConf->pLogSockName = NULL;
    /* if we do not process internal messages, we will see messages
     * from ourselves, and so we need to permit this.
     */
    pModConf->bDiscardOwnMsgs = bProcessInternalMessages;
    pModConf->bUnlink = 1;
ENDbeginCnfLoad


BEGINsetModCnf
    struct cnfparamvals *pvals = NULL;
    int i;
CODESTARTsetModCnf
    pvals = nvlstGetParams(lst, &modpblk, NULL);
    if(pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "error processing module "
                "config parameters [module(...)]");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if(Debug) {
        dbgprintf("module (global) param blk for imemlogd:\n");
        cnfparamsPrint(&modpblk, pvals);
    }

    for(i = 0 ; i < modpblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(modpblk.descr[i].name, "syssock.name")) {
            loadModConf->pLogSockName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(modpblk.descr[i].name, "syssock.unlink")) {
            loadModConf->bUnlink = (int) pvals[i].val.d.n;
        } else {
            dbgprintf("imemlogd: program error, non-handled "
              "param '%s' in beginCnfLoad\n", modpblk.descr[i].name);
        }
    }

    loadModConf->configSetViaV2Method = 1;

finalize_it:
    if(pvals != NULL)
        cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf


BEGINnewInpInst
    struct cnfparamvals *pvals;
    instanceConf_t *inst;
    int i;
CODESTARTnewInpInst
    DBGPRINTF("newInpInst (imemlogd)\n");

    pvals = nvlstGetParams(lst, &inppblk, NULL);
    if(pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS,
                    "imemlogd: required parameter are missing\n");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if(Debug) {
        dbgprintf("input param blk in imemlogd:\n");
        cnfparamsPrint(&inppblk, pvals);
    }

    CHKiRet(createInstance(&inst));

    for(i = 0 ; i < inppblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(inppblk.descr[i].name, "socket")) {
            inst->sockName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(inppblk.descr[i].name, "unlink")) {
            inst->bUnlink = (int) pvals[i].val.d.n;
        } else {
            dbgprintf("imemlogd: program error, non-handled "
              "param '%s'\n", inppblk.descr[i].name);
        }
    }
finalize_it:
CODE_STD_FINALIZERnewInpInst
    cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst


BEGINendCnfLoad
CODESTARTendCnfLoad
    loadModConf = NULL; /* done loading */
ENDendCnfLoad


/* function to generate error message if framework does not find requested ruleset */
static void
std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst)
{
    LogError(0, NO_ERRCODE, "imemlogd: ruleset '%s' for socket %s not found - "
            "using default ruleset instead", inst->pszBindRuleset,
            inst->sockName);
}
BEGINcheckCnf
    instanceConf_t *inst;
CODESTARTcheckCnf
    for(inst = pModConf->root ; inst != NULL ; inst = inst->next) {
        std_checkRuleset(pModConf, inst);
    }
ENDcheckCnf


BEGINactivateCnfPrePrivDrop
    instanceConf_t *inst;
    int nLstn;
    int i;
CODESTARTactivateCnfPrePrivDrop
    runModConf = pModConf;

    startIndexUxLocalSockets = 1;
    /* we first calculate the number of listeners so that we can
     * appropriately size the listener array. Note that we will
     * always allocate memory for the system log socket.
     */
    nLstn = 0;
    for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
        ++nLstn;
    }
    if(nLstn > 0) {
        DBGPRINTF("imemlogd: allocating memory for %d listeners\n", nLstn);
        lstn_t *const listeners_new = realloc(listeners, (1+nLstn)*sizeof(lstn_t));
        CHKmalloc(listeners_new);
        listeners = listeners_new;
        for(i = 1 ; i < nLstn ; ++i) {
            listeners[i].sockName = NULL;
            listeners[i].fd  = -1;
        }
        for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
            addListner(inst);
        }
        CHKiRet(activateListeners());
    }
finalize_it:
ENDactivateCnfPrePrivDrop


BEGINactivateCnf
CODESTARTactivateCnf
ENDactivateCnf


BEGINfreeCnf
    instanceConf_t *inst, *del;
CODESTARTfreeCnf
    free(pModConf->pLogSockName);
    for(inst = pModConf->root ; inst != NULL ; ) {
        free(inst->sockName);
        free(inst->pszBindRuleset);
        free(inst->pLogHostName);
        del = inst;
        inst = inst->next;
        free(del);
    }
ENDfreeCnf


/* This function is called to gather input. */
BEGINrunInput
CODESTARTrunInput
    if (nfd < 1) {
        LogError(errno, NO_ERRCODE, "No input sockets to read from");
        return;
    }

    /* this is an endless loop - it is terminated when the thread is
     * signalled to do so.
     */
    while(1) {
        DBGPRINTF("--------imemlogd calling poll() on %d fds\n", nfd);

        if(glbl.GetGlobalInputTermState() == 1)
            break; /* terminate input! */

        if(glbl.GetGlobalInputTermState() == 1)
            ABORT_FINALIZE(RS_RET_FORCE_TERM); /* terminate input! */
        readSocket(&(listeners[1]));
    }

finalize_it:
ENDrunInput


BEGINwillRun
CODESTARTwillRun
ENDwillRun


BEGINafterRun
    int i;
CODESTARTafterRun
    /* do cleanup here */
    if(startIndexUxLocalSockets == 1 && nfd == 1) {
        /* No sockets were configured, no cleanup needed. */
        return RS_RET_OK;
    }

    /* Close the UNIX sockets. */
    for (i = 0; i < nfd; i++)
        if (listeners[i].fd != -1)
            close(listeners[i].fd);

    /* Clean-up files. */
    for(i = startIndexUxLocalSockets; i < nfd; i++)
        if (listeners[i].sockName && listeners[i].fd != -1) {
            /* If systemd passed us a socket it is systemd's job to clean it up.
             * Do not unlink it -- we will get same socket (node) from systemd
             * e.g. on restart again.
             */

            if(listeners[i].bUnlink) {
                DBGPRINTF("imemlogd: unlinking unix socket file[%d] %s\n", i, listeners[i].sockName);
                unlink((char*) listeners[i].sockName);
            }
        }

    discardLogSockets();
    nfd = 1;
ENDafterRun


BEGINmodExit
CODESTARTmodExit
    free(listeners);
    if(pInputName != NULL)
        prop.Destruct(&pInputName);


    objRelease(parser, CORE_COMPONENT);
    objRelease(glbl, CORE_COMPONENT);
    objRelease(prop, CORE_COMPONENT);
    objRelease(datetime, CORE_COMPONENT);
    objRelease(ruleset, CORE_COMPONENT);
ENDmodExit


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
    if(eFeat == sFEATURENonCancelInputTermination)
        iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
    *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
    CHKiRet(objUse(glbl, CORE_COMPONENT));
    CHKiRet(objUse(net, CORE_COMPONENT));
    CHKiRet(objUse(prop, CORE_COMPONENT));
    CHKiRet(objUse(datetime, CORE_COMPONENT));
    CHKiRet(objUse(parser, CORE_COMPONENT));
    CHKiRet(objUse(ruleset, CORE_COMPONENT));

    DBGPRINTF("imemlogd version %s initializing\n", VERSION);
        LogError(errno, NO_ERRCODE, "memlogd version %s initializing\n", VERSION);

    /* we need to create the inputName property (only once during our lifetime) */
    CHKiRet(prop.Construct(&pInputName));
    CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imemlogd"), sizeof("imemlogd") - 1));
    CHKiRet(prop.ConstructFinalize(pInputName));

    /* right now, glbl does not permit per-instance IP address notation. As long as this
     * is the case, it is OK to query the HostIP once here at this location. HOWEVER, the
     * whole concept is not 100% clean and needs to be addressed on a higher layer.
     * TODO / rgerhards, 2012-04-11
     */
    pLocalHostIP = glbl.GetLocalHostIP();

ENDmodInit
