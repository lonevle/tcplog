// Command logrecv 是一个极简的 IETF syslog-over-TCP 接收端
// （RFC 5424 消息格式 + RFC 6587 帧格式）。用于在没有任何外部基础设施
// 的情况下验证 GoFrame 应用的日志发送是否正确：
//
//	go run ./cmd/logrecv -addr 127.0.0.1:6514
//
// 如果发送端使用的是非透明帧（LF 分隔）而不是默认的八位组计数帧，
// 加 -lf 参数。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:6514", "监听地址，host:port")
	lfFraming := flag.Bool("lf", false, "使用 LF（非透明）帧，代替默认的八位组计数帧")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *addr, err)
	}
	fmt.Printf("logrecv: 正在监听 %s，帧格式=%s\n", *addr, framingName(*lfFraming))

	var count atomic.Int64
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept 错误: %v", err)
			continue
		}
		go handle(conn, *lfFraming, &count)
	}
}

func handle(conn net.Conn, lf bool, count *atomic.Int64) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	fmt.Printf("[conn] %s 已连接\n", remote)
	r := bufio.NewReader(conn)
	for {
		msg, err := readFrame(r, lf)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "[conn] %s 读取错误: %v\n", remote, err)
			}
			fmt.Printf("[conn] %s 已断开（累计接收 %d 条）\n", remote, count.Load())
			return
		}
		fmt.Printf("[%06d] %s\n", count.Add(1), msg)
	}
}

// readFrame 从流中提取一条 syslog 消息。
func readFrame(r *bufio.Reader, lf bool) (string, error) {
	if lf {
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	// 八位组计数帧（RFC 6587）：MSG-LEN SP MSG。
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenStr))
	if err != nil || n < 0 {
		return "", fmt.Errorf("非法的帧长度 %q", lenStr)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func framingName(lf bool) string {
	if lf {
		return "lf"
	}
	return "octet-counting"
}
