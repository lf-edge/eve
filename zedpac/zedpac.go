package zedpac

import (
  "errors"
  "unsafe"
  "fmt"
)

/*
#include <pac.h>
#include <stdlib.h>
*/
import "C"

func Find_proxy_sync(pac string, url string, host string) (string, error) {
    var proxy_c *C.char = nil
    var err error = nil
    ret := ""
    pac_c := C.CString(pac)
    url_c := C.CString(url)
    host_c := C.CString(host)
    result := C.pac_find_proxy_sync(pac_c, url_c, host_c, &proxy_c)
    C.free(unsafe.Pointer(pac_c))
    C.free(unsafe.Pointer(url_c))
    C.free(unsafe.Pointer(host_c))
  
    if result != 0 || proxy_c == nil  {
       err = errors.New("zedpac: failed to compute proxy value")
       if proxy_c != nil {
          fmt.Printf(" =========> %s", C.GoString(proxy_c))
       }
    } else {
       ret = C.GoString(proxy_c)
       C.free(unsafe.Pointer(proxy_c))
    }
    return ret, err
}
