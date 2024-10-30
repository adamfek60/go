package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"time"
)

type MyData struct {
	Data    uint64
	DataEnd uint64
}
type CounterObjects struct {
	PayloadMap *ebpf.Map `ebpf:"payload_map"` // A map neve a BPF programban
}

func main() {

	// Megnyitjuk az eBPF programot tartalmazó objektum fájlt
	spec, err := ebpf.LoadCollectionSpec("counter_bpfel.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program spec: %v", err)
	}

	// Az XDP program betöltése a collection spec alapján
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["read_payload"]
	if prog == nil {
		log.Fatalf("Failed to find XDP program in the collection")
	}

	// Kapcsolódunk egy hálózati interfészhez
	ifaceName := "wlp0s20f3" //wlp0s20f3
	iface, err := net.InterfaceByIndex(3)
	if err != nil {
		log.Fatalf("Failed to find network interface %s: %v", ifaceName, err)
	}

	// XDP program csatlakoztatása az interfészhez
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer xdpLink.Close()

	var key uint32 = 0
	var value [64]byte

	time.Sleep(10 * time.Second)
	for {
		if key > 9 {
			break
		}
		// Lekérdezzük a map értékét
		if err := coll.Maps["payload_map"].Lookup(key, &value); err != nil {
			log.Fatalf("Failed to lookup map value: %v", err)
		}

		key++
		for i := 0; i < len(value); i++ {
			fmt.Printf("%02x ", value[i])
		}
		fmt.Printf("\n\n")
		
		time.Sleep(10 * time.Millisecond)
	}
	select {}
}

/*
key := uint32(0)
	var entry MyData

	if err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&entry)); err != nil {
		log.Fatalf("Failed to lookup key: %v", err)
	}

	data := (*[1500]byte)(unsafe.Pointer(uintptr(entry.Data)))[:]
	dataEnd := (*[1500]byte)(unsafe.Pointer(uintptr(entry.DataEnd)))[:]

	fmt.Print("Data: %x\n", data)
	fmt.Print("DataEnd: %x\n", dataEnd)



	var key uint32 = 0
	var value [64]byte
	var temp [64]byte

	for {
		// Lekérdezzük a map értékét
		if err := coll.Maps["payload_map"].Lookup(key, &value); err != nil {
			log.Fatalf("Failed to lookup map value: %v", err)
		}
		if value != temp {
			temp = value
			for i := 0; i < len(value); i++ {
				fmt.Printf("%02x ", value[i])
			}
			fmt.Printf("\n")
		} else {
		}

		// Kiíratjuk az eredményeket
		//fmt.Printf("Value for key %02x: %v\n", key, value)
		time.Sleep(10 * time.Millisecond)
	}

*/
