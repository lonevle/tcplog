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

// maxFrameLen 是单条 syslog 帧负载的长度上限。RFC 6587 本身未规定
// 上限，但主流实现都会限制（syslog-ng 默认 8KB，rsyslog 的
// $MaxMessageSize 默认 64KB）；这里取 1MB——宽松到足以容纳任何合理
// 日志，又能挡住损坏或恶意帧声明超大长度（例如 n=1073741824）导致
// make 直接分配巨大缓冲的问题。
const maxFrameLen = 1 << 20

// maxLenPrefix 是帧长度前缀（"MSG-LEN SP"）的字节上限。合法的
// MSG-LEN 至多十位数字（uint32 上限 4294967295），加空格共 11 字节，
// 16 已留足余量；超过它仍未读到空格即可断定流已损坏，直接断开，
// 不再为明显非法的帧继续耗费资源。
const maxLenPrefix = 16

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
	//
	// 长度前缀用 ReadSlice 而非 ReadString 读取：ReadString 在分隔符
	// 迟迟不出现时会跨缓冲无限累积，损坏或恶意的流只要持续发送不含
	// 空格的字节串就能把内存吃爆；ReadSlice 最多累积一个 bufio 缓冲
	// （默认 4KB），缓冲耗尽即返回 ErrBufferFull，内存天然封顶。此外
	// 合法前缀远小于 maxLenPrefix 字节，超限仍未出现空格即可断定
	// 帧已损坏，直接断开连接。
	lenStr, err := r.ReadSlice(' ')
	if err != nil {
		return "", err
	}
	if len(lenStr) > maxLenPrefix {
		return "", fmt.Errorf("帧长度前缀超长（%d 字节）", len(lenStr))
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(lenStr)))
	if err != nil || n < 0 || n > maxFrameLen {
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
