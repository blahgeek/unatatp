package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const BUFFER_SIZE = 16384

// Read from conn_from, forward to conn_to
func HandleForward(conn_from, conn_to *net.TCPConn, wait_group *sync.WaitGroup, log *log.Entry) {
	defer wait_group.Done()
	defer conn_to.CloseWrite()
	defer conn_from.CloseRead()

	buf := make([]byte, BUFFER_SIZE)
outer:
	for {
		read_len, err := conn_from.Read(buf)
		if err != nil || read_len <= 0 {
			log.WithError(err).WithField("read_len", read_len).Trace("Read finished, to close")
			break
		}
		log.WithField("len", read_len).Trace("Read buffer")

		for offset := 0; offset < read_len; {
			write_len, err := conn_to.Write(buf[offset:read_len])
			if err != nil || write_len <= 0 {
				log.WithError(err).WithField("write_len", write_len).Trace("Write finished, to close")
				break outer
			}
			offset += write_len
		}
		log.WithField("len", read_len).Trace("Write buffer")
	}
}

// Handle accepted tcp connection. Make a new connection from myself and forward between them
func HandleTCPConnection(conn *net.TCPConn, bind_ip_factory func(net.IP) net.IP, conn_id int64) {
	defer conn.Close()

	addr_src, addr_src_ok := conn.RemoteAddr().(*net.TCPAddr)
	addr_dst, addr_dst_ok := conn.LocalAddr().(*net.TCPAddr)
	if !addr_src_ok || !addr_dst_ok {
		log.Error("Invalid src/dst addr")
		return
	}

	log := log.WithField("src", addr_src).WithField("dst", addr_dst).WithField("id", conn_id)

	bind_ip := bind_ip_factory(addr_src.IP)
	log.WithField("bind_ip", bind_ip).Debug("New tcp connection, making next connection...")
	conn_next, err := net.DialTCP("tcp", &net.TCPAddr{IP: bind_ip}, addr_dst)
	if err != nil {
		log.WithError(err).Error("DialTCP")
		return
	}
	defer conn_next.Close()

	log.WithField("next_src", conn_next.LocalAddr()).WithField("next_dst", conn_next.RemoteAddr()).
		Debug("Made next connection")

	wait_group := new(sync.WaitGroup)
	wait_group.Add(2)

	go HandleForward(conn, conn_next, wait_group, log.WithField("dir", 0))
	go HandleForward(conn_next, conn, wait_group, log.WithField("dir", 1))
	wait_group.Wait()
	log.Debug("Connection closed")
}

func ServeForever(listen_addr string, bind_ip_factory func(net.IP) net.IP, conn_id *int64) {
	listenaddr, err := net.ResolveTCPAddr("tcp", listen_addr)
	if err != nil {
		log.WithError(err).Fatal("ResolveTCPAddr")
	}

	listener, err := net.ListenTCP("tcp", listenaddr)
	if err != nil {
		log.WithError(err).Fatal("ListenTCP")
	}
	defer listener.Close()
	log.Info("Listening on ", listener.Addr())

	listener_sys, err := listener.SyscallConn()
	if err != nil {
		log.WithError(err).Fatal("listener.SyscallConn")
	}

	listener_sys.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			log.WithError(err).Fatal("SetsockoptInt IP_TRANSPARENT")
		}
	})

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.WithError(err).Fatal("AcceptTCP")
		}
		go HandleTCPConnection(conn, bind_ip_factory, atomic.AddInt64(conn_id, 1))
	}
}

func main() {
	flag_verbose := flag.Int("verbose", 0, "Be verbose. 1: debug, 2: trace")
	flag_port := flag.Int("port", 9999, "Port to listen")
	flag_bind_ipv4 := flag.String("bind_ipv4", "", "IPv4 address to bind for outgoing connection")
	flag_bind_ipv6_prefix := flag.String("bind_ipv6_prefix", "",
		"IPv6 prefix to bind for outgoing connection. NOTE: this is a prefix instead of address, it will work like stateless NAT")
	flag.Parse()

	var bind_ipv4 net.IP
	if len(*flag_bind_ipv4) > 0 {
		bind_ipv4 = net.ParseIP(*flag_bind_ipv4)
		if bind_ipv4 == nil {
			log.WithField("bind_ipv4", *flag_bind_ipv4).Fatal("Cannot parse ipv4 addr")
		}
	}

	var bind_ipv6_prefix *net.IPNet
	if len(*flag_bind_ipv6_prefix) > 0 {
		_, bind_ipv6_prefix, _ = net.ParseCIDR(*flag_bind_ipv6_prefix)
		if bind_ipv6_prefix == nil {
			log.WithField("bind_ipv6_prefix", *flag_bind_ipv6_prefix).Fatal("Cannot parse ipv6 prefix")
		}
	}

	if *flag_verbose >= 2 {
		log.SetLevel(log.TraceLevel)
	} else if *flag_verbose >= 1 {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000",
	})

	var conn_id int64 = 0
	go ServeForever(fmt.Sprintf("127.0.0.1:%d", *flag_port),
		func(source_addr net.IP) net.IP {
			if bind_ipv4 == nil {
				return nil
			}
			return bind_ipv4
		}, &conn_id)
	go ServeForever(fmt.Sprintf("[::1]:%d", *flag_port),
		func(source_addr net.IP) net.IP {
			if bind_ipv6_prefix == nil {
				return nil
			}
			prefix_len, _ := bind_ipv6_prefix.Mask.Size()
			new_addr := make([]byte, 16)

			for i := 0; i < prefix_len/8; i++ {
				new_addr[i] = bind_ipv6_prefix.IP[i]
			}
			if prefix_len < 128 {
				i := prefix_len / 8
				m := byte((1 << (8 - (prefix_len % 8))) - 1)
				new_addr[i] = (bind_ipv6_prefix.IP[i] & ^m) | (source_addr[i] & m)
			}
			for i := prefix_len/8 + 1; i < 16; i++ {
				new_addr[i] = source_addr[i]
			}

			return new_addr
		}, &conn_id)

	select {}
}
