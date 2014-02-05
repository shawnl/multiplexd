package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"github.com/coreos/go-systemd/activation"
)

type matcher func(packet []byte, length int) (host string, port int)

func copyAndClose(w io.Writer, r io.ReadCloser) {
	io.Copy(w, r)
	r.Close()
}

func handleConnection(c net.Conn, patterns []matcher) {
	var d net.Conn
	buf := make([]byte, 4096, 4096)
	oobbuf := make([]byte, 512, 512)

	defer c.Close()

	conn := c.(*net.TCPConn)
	f, _ := conn.File()
	length, _, _, from, err := syscall.Recvmsg(int(f.Fd()), buf, oobbuf, syscall.MSG_PEEK)
	if err != nil {
		fmt.Println(from, err)
		return
	}
	f.Close()

	for n := 0;;n += 1 {
		if len(patterns) == n {
			fmt.Println(c.RemoteAddr, "Protocol not recognized")
			return
		}

		host, port := patterns[n](buf, length)
		if port > 0 {
			d, err = net.Dial("tcp", fmt.Sprint(host, ":", port))
			if err != nil {
				fmt.Println(c.RemoteAddr, err)
				return
			}

			break
		}
	}

	go copyAndClose(c, d)
	io.Copy(d, c)
}

func parseHostPort(arg string) (host string, port int, err error) {
	if strings.Index(arg, ":") == -1 {
		host = "localhost"
		port, err = strconv.Atoi(arg)
		return
	}
	n, err := strconv.Atoi(arg[strings.Index(arg, ":")+1:])
	return arg[:strings.Index(arg, ":")], n, err
}

func handleListener(c net.Listener, patterns []matcher) {
	for {
		conn, err := c.Accept()
		if err != nil {
			fmt.Println("Accept failed:", err)
			continue
		}
		go handleConnection(conn, patterns)
	}
}

func usage() {
	fmt.Println("multiplexd [[listenhost:]port..] [--ssl [host:]port|--ssh [host:]port|--openvpn [host:]port|--regex regex [host:]port..]")
	os.Exit(1)
}

func main() {
	var patterns []matcher
	var n int

	if len(os.Args) < 2 {
		usage()
	}

	for n = 1;;n += 1 {
		if bytes.Equal([]byte(os.Args[n])[:2], []byte("--")) {
			break
		}

		if n == len(os.Args) - 1 {
			usage()
		}
	}

	firstFilterArg := n

	for ;n < len(os.Args) - 1; n += 2 {
		if bytes.Equal([]byte(os.Args[n]), []byte("--regex")) {
			if len(os.Args) < n+2 {
				fmt.Println("Not enough arguments to --regex")
				os.Exit(1)
			}
			host, port, err := parseHostPort(os.Args[n+2])
			if err != nil {
				fmt.Println("Bad host:port specification:", os.Args[n+2], host, port, err)
				os.Exit(1)
			}

			r, err := regexp.Compile(os.Args[n+1])
			if err != nil {
				fmt.Println("Failed to compile regular expression:", os.Args[n+1], err)
				os.Exit(1)
			}

			patterns = append(patterns, (func(packet []byte, length int) (h string, p int) {
				h = host
				if r.Match(packet) {
					p = port
				}
				return
			}))

			n += 1
			continue
		}

		host, port, err := parseHostPort(os.Args[n+1])
		if err != nil {
			fmt.Println("Bad host:port specification:", os.Args[n+1], host, port, err)
			os.Exit(1)
		}
		if bytes.Equal([]byte(os.Args[n]), []byte("--ssh")) {
			patterns = append(patterns, (func(packet []byte, length int) (h string, p int) {
				h = host
				if bytes.Equal(packet[:4], []byte("SSH-")) {
					p = port
				}
				return
			}))
		} else if bytes.Equal([]byte(os.Args[n]), []byte("--ssl")) {
			patterns = append(patterns, (func(pack []byte, length int) (h string, p int) {
				h = host
				if bytes.Equal(pack[:2], []byte{0x16, 0x03}) && pack[3] >= 0x00 && pack[3] <= 0x03 {
					p = port
				}
				return
			}))
		} else if bytes.Equal([]byte(os.Args[n]), []byte("--openvpn")) {
			patterns = append(patterns, (func(pack []byte, length int) (h string, p int) {
				var l uint16
				h = host
				binary.Read(bytes.NewReader(pack), binary.BigEndian, &l)
				if l == uint16(length-2) {
					p = port
				}
				return
			}))
		}
	}

	listeners, err := activation.Listeners(true)

	if err != nil {
		panic(err)
	}

	// If we recieved any sockets from systemd do not open our own listeners
	if len(listeners) > 0 {
		for _, ln := range listeners {
			go handleListener(ln, patterns)
		}
	} else {
		if firstFilterArg == 1 {
			fmt.Println("No listen port(s) specified and did not recieve and not being systemd socket activated")
			os.Exit(1)
		}

		for n = 1;n < firstFilterArg;n += 1 {
			host, port, err := parseHostPort(os.Args[n])

			if err != nil {
				fmt.Println("Bad Listen host:port:", os.Args[n])
				break
			}

			if bytes.Compare([]byte(host), []byte("localhost")) == 0 {
				host = "0.0.0.0"
			}

			ln, err := net.Listen("tcp", fmt.Sprint(host, ":", port))
			if err != nil {
				fmt.Println("Listen failed:", err)
				break
			}

			go handleListener(ln, patterns)
		}
	}
}
