// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Inspired by https://www.codenotary.com/blog/ebpf-linux-immudb/ and
//               https://raw.githubusercontent.com/iovisor/bcc/master/tools/tcpconnect.py

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/codenotary/immudb/pkg/client"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/renstrom/shortuuid"
	"google.golang.org/grpc/metadata"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("trace_connect_entry");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;


    if (ipver == 4) {
	    struct ipv4_data_t data4 = {.pid = pid};
	    data4.saddr = skp->__sk_common.skc_rcv_saddr;
	    data4.daddr = skp->__sk_common.skc_daddr;
	    data4.lport = lport;
	    data4.dport = ntohs(dport);
	    bpf_get_current_comm(&data4.task, sizeof(data4.task));
	    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
	    struct ipv6_data_t data6 = {.pid = pid};
	    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
	    skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
	    skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	    data6.lport = lport;
	    data6.dport = ntohs(dport);
	    bpf_get_current_comm(&data6.task, sizeof(data6.task));
	    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    bpf_trace_printk("trace_connect_v4_return");
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    bpf_trace_printk("trace_connect_v6_return");
    return trace_connect_return(ctx, 6);
}
`

type v4Event struct {
	Pid   uint32
	Saddr uint32
	Daddr uint32
	Lport uint16
	Dport uint16
	Comm  [16]byte
}

type Uint128 struct {
	Lo, Hi uint64
}

type v6Event struct {
	Pid   uint32
	Saddr Uint128
	Daddr Uint128
	Lport uint16
	Dport uint16
	Comm  [16]byte
}

type Entry struct {
	Pid     uint32 `json:pid`
	DPort   uint16 `json:dport`
	Command string `json:command`
	Dst     string `json:dst`
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	connect4_trace, err := m.LoadKprobe("trace_connect_entry")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_entry: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKprobe("tcp_v4_connect", connect4_trace, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tcp_v4_connect kprobe: %s\n", err)
		os.Exit(1)
	}

	connect4_ret_trace, err := m.LoadKprobe("trace_connect_v4_return")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_return kprobe: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKretprobe("tcp_v4_connect", connect4_ret_trace, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tcp_v4_connect kretprobe: %s\n", err)
		os.Exit(1)
	}

	connect6_trace, err := m.LoadKprobe("trace_connect_entry")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_entry: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKprobe("tcp_v6_connect", connect6_trace, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tcp_v6_connect kprobe: %s\n", err)
		os.Exit(1)
	}

	connect6_ret_trace, err := m.LoadKprobe("trace_connect_v6_return")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v6_return kprobe: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKretprobe("tcp_v4_connect", connect6_ret_trace, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tcp_v6_connect kretprobe: %s\n", err)
		os.Exit(1)
	}

	tablev4 := bpf.NewTable(m.TableId("ipv4_events"), m)

	channelv4 := make(chan []byte)

	perfMapv4, err := bpf.InitPerfMap(tablev4, channelv4, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init ipv4_events perf map: %s\n", err)
		os.Exit(1)
	}

	tablev6 := bpf.NewTable(m.TableId("ipv6_events"), m)

	channelv6 := make(chan []byte)

	perfMapv6, err := bpf.InitPerfMap(tablev6, channelv6, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init ipv6_events perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		c, err := client.NewImmuClient(client.DefaultOptions())
		if err != nil {
			log.Fatal(err)
		}

		ctx := context.Background()
		// login with default username and password and storing a token
		lr, err := c.Login(ctx, []byte(`immudb`), []byte(`immudb`))
		if err != nil {
			log.Fatal(err)
		}
		// set up an authenticated context that will be required in future operations
		md := metadata.Pairs("authorization", lr.Token)
		ctx = metadata.NewOutgoingContext(context.Background(), md)

		log.Printf("Connected to immudb")

		for {
			var eventv4 v4Event
			var eventv6 v6Event
			var pid uint32
			var dport uint16
			var comm string
			var dst string

			select {
			case datav4 := <-channelv4:
				ipByte := make([]byte, 4)
				err := binary.Read(bytes.NewBuffer(datav4), binary.LittleEndian, &eventv4)
				if err != nil {
					fmt.Printf("failed to decode ipv4 received data: %s\n", err)
					continue
				}
				comm = string(eventv4.Comm[:bytes.IndexByte(eventv4.Comm[:], 0)])
				pid = eventv4.Pid
				binary.LittleEndian.PutUint32(ipByte, eventv4.Daddr)
				ip := net.IP(ipByte)
				dst = ip.String()
				dport = eventv4.Dport
			case datav6 := <-channelv6:
				err := binary.Read(bytes.NewBuffer(datav6), binary.LittleEndian, &eventv6)
				if err != nil {
					fmt.Printf("failed to decode ipv6 received data: %s\n", err)
					continue
				}
				comm = string(eventv6.Comm[:bytes.IndexByte(eventv6.Comm[:], 0)])
				pid = eventv6.Pid
				//TODO parse ipv6
				continue
			}

			entry := Entry{Pid: pid, Command: comm, Dst: dst, DPort: dport}
			json, err := json.MarshalIndent(entry, "", "\t")
			if err != nil {
				log.Fatal(err)
			}
			key := fmt.Sprintf("IPSink:%d:%s", time.Now().UnixNano(), shortuuid.New())
			_, err = c.Set(ctx, []byte(key), json)
			if err != nil {
				log.Fatal(err)
			}
		}
	}()

	perfMapv4.Start()
	perfMapv6.Start()
	<-sig
	perfMapv4.Stop()
	perfMapv6.Stop()
}
