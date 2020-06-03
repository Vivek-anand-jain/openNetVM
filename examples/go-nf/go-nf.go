package main

// #include <stdlib.h>
// #include <rte_lcore.h>
// #include <rte_common.h>
// #include <rte_ip.h>
// #include <rte_mbuf.h>
// 
// #include "onvm_nflib.h"
// #include "onvm_pkt_helper.h"
import "C"
import (
	"fmt"
)

//export Handler
func Handler(pkt * C.struct_rte_mbuf, meta * C.struct_onvm_pkt_meta,
                    nf_local_ctx * C.struct_onvm_nf_local_ctx) int {
  fmt.Println("packet received!")
  meta.action = C.ONVM_NF_ACTION_DROP
  return 0;
}

func main() {}
