package main

// #include <stdlib.h>
// #include <rte_lcore.h>
// #include <rte_common.h>
// #include <rte_ip.h>
// #include <rte_mbuf.h>
// #include <onvm_nflib.h>
// #include <onvm_pkt_helper.h>
import "C"
import (
	"fmt"
    "time"
)

var done = make(chan bool, 1)
var receiveA = make(chan bool, 1)
var receiveB = make(chan bool, 1)

var i int

//export Handler
func Handler(pkt * C.struct_rte_mbuf, meta * C.struct_onvm_pkt_meta,
                    nf_local_ctx * C.struct_onvm_nf_local_ctx) int {
    i++
    fmt.Println("packet received!")
    meta.action = C.ONVM_NF_ACTION_DROP
    if i % 2 == 0 {
        receiveA <- true
    } else {
        receiveB <- true
    }
    return 0;
}

var pktmbuf_pool * C.struct_rte_mempool
var nf_local_ctx  * C.struct_onvm_nf_local_ctx

func thread(name string, receive chan bool) {
    ticker := time.NewTicker(5000 * time.Millisecond)
    for {
        select {
        case <-receive:
            fmt.Println(name, " Received a packet")
            send_packet()
        case <-done:
            fmt.Println(name, "Done")
            return
        case t := <-ticker.C:
            fmt.Println(name, "Tick at", t)
        }
    }
}

func send_packet() {
    pkt := C.rte_pktmbuf_alloc(pktmbuf_pool);
    if (pkt == nil) {
        fmt.Printf("Failed to allocate packets\n");
        return;
    }

    C.rte_pktmbuf_append(pkt, 12);

    pmeta := C.onvm_get_pkt_meta(pkt);
    pmeta.destination = 100;
    pmeta.action = C.ONVM_NF_ACTION_TONF;

    // The below line is not working
    // C.onvm_nflib_return_pkt(nf_local_ctx.nf, pkt);
}

//export Init
func Init(local_nf_ctx * C.struct_onvm_nf_local_ctx) int {
    nf_local_ctx = local_nf_ctx
    pktmbuf_pool = C.rte_mempool_lookup(C.CString("MProc_pktmbuf_pool"));
    if (pktmbuf_pool == nil) {
        return -1
    }

    go thread("A", receiveA)
    go thread("B", receiveB)


    fmt.Println("Init Done")
    return 0;
}

//export Done
func Done() {
    done <- true
    done <- true
}

func main() {}
