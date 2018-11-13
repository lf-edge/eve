package zedpac

import (
  "unsafe"
  "fmt"
  "strings"
  "sync"
)

/*
#include <pac.h>
#include <stdlib.h>
#include <stdio.h>

static char* buffer;
static char* buf_ptr;
static int buf_size;

static void log(int level, const char *buf) {
    while (*buf && (buf_ptr - buffer < buf_size - 1)) {
       *buf_ptr++ = *buf++;
    }
    *buf_ptr = '\0';
}

static void init_log(char *buf, int size) {
    buffer  = buf;
    buf_ptr = buf;
    buf_size = size;
    pac_set_log_fn(&log);
}
*/
import "C"

// FIXME: rewrite logging in pac.c to make MT-friendly
var mux sync.Mutex
var log [10*1024]byte

func Find_proxy_sync(pac, url, host string) (string, error) {
    var proxy_c *C.char = nil
    var err error = nil
    ret := ""
    pac_c := C.CString(pac)
    url_c := C.CString(url)
    host_c := C.CString(host)

    mux.Lock()    
    C.init_log((*C.char)(unsafe.Pointer(&log[0])), C.int(len(log)))
    result := C.pac_find_proxy_sync(pac_c, url_c, host_c, &proxy_c)
    mux.Unlock()

    C.free(unsafe.Pointer(pac_c))
    C.free(unsafe.Pointer(url_c))
    C.free(unsafe.Pointer(host_c))
  
    if result != 0 || proxy_c == nil  {
       err = fmt.Errorf("zedpac: failed to compute proxy value, javascript log: %s", strings.TrimRight(string(log[:]), "\x00"))
    } else {
       ret = C.GoString(proxy_c)
       C.free(unsafe.Pointer(proxy_c))
    }
    return ret, err
}
