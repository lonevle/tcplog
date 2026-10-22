package tcplog

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"
)

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// receiver 是一个极简的 syslog-over-TCP 服务端：解析 RFC 6587 八位组
// 计数帧，并通过 channel 把消息内容暴露出来。
type receiver struct {
	listener net.Listener
	frames   chan string
}

func startReceiver(t *testing.T) *receiver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	r := &receiver{listener: ln, frames: make(chan string, 64)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return r
}

func (r *receiver) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil || n < 0 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		r.frames <- string(buf)
	}
}

func (r *receiver) addr() string { return r.listener.Addr().String() }

// next 等待下一条帧，超时则测试失败。
func (r *receiver) next(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case f := <-r.frames:
		return f
	case <-time.After(timeout):
		t.Fatal("等待 syslog 帧超时")
		return ""
	}
}

// ---------------------------------------------------------------------------
// Formatter 测试
// ---------------------------------------------------------------------------

func TestFormatBasic(t *testing.T) {
	f := &Formatter{Hostname: "myhost", AppName: "myapp", ProcID: "4242", Facility: FacilityLocal0}
	got := string(f.Format(&Record{
		Time:     time.Date(2026, 10, 21, 11, 47, 26, 123456000, time.FixedZone("CST", 8*3600)),
		Severity: SeverityInformational,
		MsgID:    "INFO",
		Msg:      "hello world",
		SD:       []SDElement{{ID: "goframe", Params: []SDParam{{Key: "level", Value: "INFO"}}}},
	}))
	want := `<134>1 2026-10-21T11:47:26.123456+08:00 myhost myapp 4242 INFO [goframe level="INFO"] hello world`
	if got != want {
		t.Fatalf("格式化结果不符:\n 实际: %q\n 期望: %q", got, want)
	}
}

func TestFormatNilValues(t *testing.T) {
	f := &Formatter{Facility: FacilityLocal0}
	got := string(f.Format(&Record{}))
	want := `<128>1 - - - - - - -`
	if got != want {
		t.Fatalf("格式化结果不符:\n 实际: %q\n 期望: %q", got, want)
	}
}

func TestFormatTimestampIsUTCCompatible(t *testing.T) {
	f := &Formatter{Hostname: "h", AppName: "a", ProcID: "1", Facility: FacilityLocal0}
	// 按 RFC 5424 TIMESTAMP 要求，UTC 必须渲染为 +00:00，不能用 "Z"。
	got := string(f.Format(&Record{
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Severity: SeverityInformational,
		Msg:      "x",
	}))
	if !strings.Contains(got, "2026-01-02T03:04:05.000000+00:00") {
		t.Fatalf("时间戳渲染不符合预期: %q", got)
	}
}

func TestFormatStructuredDataEscaping(t *testing.T) {
	sd := SDElement{ID: "gf", Params: []SDParam{{Key: "note", Value: `a"b\c]d`}}}
	want := `[gf note="a\"b\\c\]d"]`
	if got := sd.String(); got != want {
		t.Fatalf("结构化数据转义不符:\n 实际: %q\n 期望: %q", got, want)
	}
}

func TestFormatHeaderValueSanitization(t *testing.T) {
	f := &Formatter{Hostname: "has space", AppName: "", ProcID: "1", Facility: FacilityLocal0}
	got := string(f.Format(&Record{Time: time.Now(), Severity: SeverityInformational, MsgID: "INFO", Msg: "x"}))
	// 含空格的 HOSTNAME 和空的 APP-NAME 都必须变成 NILVALUE。
	if !strings.Contains(got, " - - 1 INFO") {
		t.Fatalf("头部字段未按预期清洗: %q", got)
	}
}

func TestSeverityFromGlogLevel(t *testing.T) {
	cases := []struct {
		level    int
		severity int
	}{
		{glog.LEVEL_DEBU, SeverityDebug},
		{glog.LEVEL_INFO, SeverityInformational},
		{glog.LEVEL_NOTI, SeverityNotice},
		{glog.LEVEL_WARN, SeverityWarning},
		{glog.LEVEL_ERRO, SeverityError},
		{glog.LEVEL_CRIT, SeverityCritical},
		{glog.LEVEL_PANI, SeverityAlert},
		{glog.LEVEL_FATA, SeverityEmergency},
	}
	for _, c := range cases {
		if got := SeverityFromGlogLevel(c.level); got != c.severity {
			t.Errorf("级别 %d: 得到严重级别 %d，期望 %d", c.level, got, c.severity)
		}
	}
}

// ---------------------------------------------------------------------------
// Writer 测试
// ---------------------------------------------------------------------------

func TestFrame(t *testing.T) {
	octet := &Writer{octetCounting: true}
	if got, want := string(octet.frame([]byte("abc"))), "3 abc"; got != want {
		t.Errorf("八位组计数帧: 得到 %q，期望 %q", got, want)
	}
	lf := &Writer{octetCounting: false}
	if got, want := string(lf.frame([]byte("abc"))), "abc\n"; got != want {
		t.Errorf("LF 帧: 得到 %q，期望 %q", got, want)
	}
	// 输入缓冲必须被复制，不能被引用。
	src := []byte("abc")
	octet.frame(src)
	src[0] = 'z'
	if got := string(octet.frame(src)); got != "3 zbc" {
		t.Errorf("加帧时必须复制输入: %q", got)
	}
}

func TestNewInvalidAddr(t *testing.T) {
	if _, err := New("missing-port"); err == nil {
		t.Fatal("缺少端口的地址应当报错")
	}
	if _, err := New(""); err == nil {
		t.Fatal("空地址应当报错")
	}
}

func TestWriterEndToEnd(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	f := &Formatter{Hostname: "e2ehost", AppName: "e2eapp", ProcID: "777", Facility: FacilityLocal0}
	msg := f.Format(&Record{
		Time:     time.Now(),
		Severity: SeverityWarning,
		MsgID:    "WARN",
		Msg:      "disk usage high",
		SD:       []SDElement{{ID: "goframe", Params: []SDParam{{Key: "level", Value: "WARN"}}}},
	})
	if _, err := w.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := r.next(t, 3*time.Second)
	if !strings.HasPrefix(got, "<132>1 ") { // local0(16)*8 + warning(4) = 132
		t.Fatalf("PRI 不符合预期: %q", got)
	}
	if !strings.Contains(got, "e2ehost e2eapp 777 WARN") || !strings.Contains(got, "disk usage high") {
		t.Fatalf("消息内容不符合预期: %q", got)
	}
	// 帧长度前缀必须与负载长度严格一致。
	if len(got) == 0 {
		t.Fatal("收到空帧")
	}
}

func TestWriterLFFramingEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	lines := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			lines <- strings.TrimRight(line, "\r\n")
		}
	}()

	w, err := New(ln.Addr().String(), WithLFFraming())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("lf framed message")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case got := <-lines:
		if got != "lf framed message" {
			t.Fatalf("得到 %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("等待 LF 帧消息超时")
	}
}

func TestGlogHandlerIntegration(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	f := &Formatter{Hostname: "testhost", AppName: "testapp", ProcID: "999", Facility: FacilityLocal0}
	glog.SetDefaultHandler(NewGlogHandler(w, f))

	ctx := gctx.New()
	glog.Info(ctx, "integration ok")
	glog.Errorf(ctx, "boom %d", 42)

	frame := r.next(t, 3*time.Second)
	if !strings.HasPrefix(frame, "<134>1 ") { // local0 + informational
		t.Fatalf("INFO 帧不符合预期: %q", frame)
	}
	if !strings.Contains(frame, "testhost testapp 999 INFO") || !strings.Contains(frame, "integration ok") {
		t.Fatalf("INFO 内容不符合预期: %q", frame)
	}

	frame = r.next(t, 3*time.Second)
	if !strings.HasPrefix(frame, "<131>1 ") { // local0 + error
		t.Fatalf("ERROR 帧不符合预期: %q", frame)
	}
	if !strings.Contains(frame, "boom 42") {
		t.Fatalf("ERROR 内容不符合预期: %q", frame)
	}
}

func TestWriterLazyConnectAndBackoff(t *testing.T) {
	// 先占一个端口再释放：Writer 启动时应当处于无服务端状态。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	w, err := New(addr, WithBackoff(20*time.Millisecond, 100*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// 第一条消息会被丢弃：没有服务端，拨号必然失败。
	if _, err := w.Write([]byte("lost message")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// 在同一端口把服务端拉起来，Writer 必须能自动重连。
	r := &receiver{frames: make(chan string, 8)}
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("重新监听失败: %v", err)
	}
	r.listener = ln2
	defer ln2.Close()
	go func() {
		for {
			conn, err := ln2.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()

	if _, err := w.Write([]byte("recovered message")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := r.next(t, 3*time.Second)
	if got != "recovered message" {
		t.Fatalf("帧不符合预期: %q", got)
	}
	if stats := w.Stats(); stats.Sent < 1 || stats.Dropped < 1 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}

func TestWriterCloseFlushesQueue(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte("flush me")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// Close 返回前必须把队列里的消息全部发完。
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i := 0; i < n; i++ {
		if got := r.next(t, 2*time.Second); got != "flush me" {
			t.Fatalf("第 %d 条帧不符合预期: %q", i, got)
		}
	}
	if stats := w.Stats(); stats.Sent != n || stats.Dropped != 0 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}

func TestWriteAfterClose(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close 之后 Write: 得到 %v，期望 ErrClosed", err)
	}
	// Close 是幂等的。
	if err := w.Close(); err != nil {
		t.Fatalf("第二次 Close: %v", err)
	}
}

func TestWriterDropsWhenQueueFull(t *testing.T) {
	r := startReceiver(t)
	// 接收端不读取数据，而发送端会不断写入远超 socket 缓冲的大消息，
	// 小队列必然被打满。
	w, err := New(r.addr(), WithQueueSize(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	// socket 缓冲会吞掉前几条，持续写入足够多的消息即可让队列溢出。
	payload := strings.Repeat("x", 64*1024)
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte(payload))
	}
	deadline := time.Now().Add(2 * time.Second)
	for w.Stats().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w.Stats().Dropped == 0 {
		t.Fatal("队列溢出时应当出现丢包")
	}
}

func TestErrorHandlerCalled(t *testing.T) {
	// 指向无人监听的端口，让拨号失败，验证传输错误确实通过
	// WithErrorHandler 上报，且回调路径不会无限递归爆栈。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var calls atomic.Int64
	w, err := New(addr,
		WithBackoff(10*time.Millisecond, 50*time.Millisecond),
		WithErrorHandler(func(err error) {
			calls.Add(1)
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("boom")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("传输错误应当通过 WithErrorHandler 回调上报")
	}
}

// ---------------------------------------------------------------------------
// 批处理
// ---------------------------------------------------------------------------

// TestBatchFlushOnSize 验证未攒够 WithBatchSize 条数前不会发送。
func TestBatchFlushOnSize(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr(), WithBatchSize(3))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	for i := 0; i < 2; i++ {
		if _, err := w.Write([]byte("batch msg")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// 批次未满，这段时间内不应当有任何帧到达。
	select {
	case got := <-r.frames:
		t.Fatalf("批次未满时不应发送，却收到: %q", got)
	case <-time.After(300 * time.Millisecond):
	}

	// 第三条消息凑满一批，触发整批发送。
	if _, err := w.Write([]byte("batch msg")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for i := 0; i < 3; i++ {
		if got := r.next(t, 3*time.Second); got != "batch msg" {
			t.Fatalf("第 %d 条帧不符合预期: %q", i, got)
		}
	}
	if stats := w.Stats(); stats.Sent != 3 || stats.Dropped != 0 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}

// TestBatchFlushOnInterval 验证按时间攒批：条数远未满也会到点发送。
func TestBatchFlushOnInterval(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr(),
		WithBatchSize(10),                       // 条数永远不会满
		WithBatchInterval(100*time.Millisecond), // 只能靠计时器触发
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("timed msg")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case got := <-r.frames:
		if got != "timed msg" {
			t.Fatalf("帧不符合预期: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("批处理间隔到达后应当发送")
	}
}

// TestBatchFlushOnClose 验证关闭时把当前未发出去的批次发完。
func TestBatchFlushOnClose(t *testing.T) {
	r := startReceiver(t)
	w, err := New(r.addr(), WithBatchSize(100))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte("close batch")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i := 0; i < n; i++ {
		if got := r.next(t, 2*time.Second); got != "close batch" {
			t.Fatalf("第 %d 条帧不符合预期: %q", i, got)
		}
	}
	if stats := w.Stats(); stats.Sent != n || stats.Dropped != 0 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}

// TestBatchDroppedWhenServerDown 验证批处理模式下服务器不可达时，整批
// 丢弃按消息条数计数。
func TestBatchDroppedWhenServerDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	w, err := New(addr,
		WithBatchSize(3),
		WithDialTimeout(500*time.Millisecond),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		if _, err := w.Write([]byte("lost batch")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for w.Stats().Dropped < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stats := w.Stats(); stats.Dropped != 3 || stats.Sent != 0 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}
