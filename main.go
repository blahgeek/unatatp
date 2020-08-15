package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
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
func HandleTCPConnection(conn *net.TCPConn, conn_id int64) {
	defer conn.Close()

	addr_src, addr_src_ok := conn.RemoteAddr().(*net.TCPAddr)
	addr_dst, addr_dst_ok := conn.LocalAddr().(*net.TCPAddr)
	if !addr_src_ok || !addr_dst_ok {
		log.Error("Invalid src/dst addr")
		return
	}

	log := log.WithField("src", addr_src).WithField("dst", addr_dst).WithField("id", conn_id)

	log.Debug("New tcp connection, making next connection...")

	conn_next, err := net.DialTCP("tcp4", nil, addr_dst)
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

func main() {
	flag_verbose := flag.Int("verbose", 0, "Be verbose. 1: debug, 2: trace")
	flag_port := flag.Int("port", 9999, "Port to listen")
	flag.Parse()

	if *flag_verbose >= 2 {
		log.SetLevel(log.TraceLevel)
	} else if *flag_verbose >= 1 {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000",
	})

	listenaddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("127.0.0.1:%d", *flag_port))
	if err != nil {
		log.WithError(err).Fatal("ResolveTCPAddr")
	}

	listener, err := net.ListenTCP("tcp4", listenaddr)
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
			log.WithError(err).Fatal("SetsockoptInt")
		}
	})

	var conn_id int64 = 0
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.WithError(err).Fatal("AcceptTCP")
		}
		conn_id++
		go HandleTCPConnection(conn, conn_id)
	}

}
