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

// maxFrameLen 限制测试接收端接受的单帧负载长度，与 cmd/logrecv 的
// 防御保持一致：损坏帧声明超大长度（例如 1GB）时直接断开，而不是
// make 出巨大缓冲。测试中最大的合法消息是 64KB（TestWriterDrops-
// WhenQueueFull），1MB 上限远高于此。
const maxFrameLen = 1 << 20

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
		if err != nil || n < 0 || n > maxFrameLen {
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

// TestSDElementEmptyNames 验证空 SD-ID 与空 SD-PARAM-NAME 的兜底命名
// 语义正确：SD-ID 是元素名应兜底为 "elem"，参数名才兜底为 "param"
// ——之前两者共用 "param"，空 ID 的元素名会被误导性地渲染成 "param"。
func TestSDElementEmptyNames(t *testing.T) {
	sd := SDElement{Params: []SDParam{{Key: "", Value: "v"}}}
	if got, want := sd.String(), `[elem param="v"]`; got != want {
		t.Fatalf("空名兜底不符:\n 实际: %q\n 期望: %q", got, want)
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

func TestFormatHeaderRejectsNonASCII(t *testing.T) {
	f := &Formatter{Hostname: "中文主机名", AppName: "app", ProcID: "1", Facility: FacilityLocal0}
	got := string(f.Format(&Record{
		Time:     time.Now(),
		Severity: SeverityInformational,
		MsgID:    "MSG ID", // 含空格
		Msg:      "x",
	}))
	// RFC 5424 要求 HEADER 字段为可打印 US-ASCII：非 ASCII 的 HOSTNAME
	// 与含空格的 MSGID 都必须渲染为 NILVALUE。
	if !strings.Contains(got, " - app 1 - - x") {
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

// TestWithBackoffValidation 验证退避参数的边界处理：max 非法（非正或
// 小于最终生效的 min）时必须兜底提升到 min，保证 minBackoff <=
// maxBackoff 恒成立——否则 scheduleBackoff 的指数增长永远不触发，
// 退避被卡死在 min 上，且用户配置的上限被静默丢弃。
func TestWithBackoffValidation(t *testing.T) {
	cases := []struct {
		name             string
		min, max         time.Duration
		wantMin, wantMax time.Duration
	}{
		{"max为零", 30 * time.Second, 0, 30 * time.Second, 30 * time.Second},
		{"max为负", 30 * time.Second, -time.Second, 30 * time.Second, 30 * time.Second},
		{"max小于min", 10 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second},
		{"max小于默认min", 0, 100 * time.Millisecond, defaultMinBackoff, defaultMinBackoff},
		{"正常区间", 100 * time.Millisecond, 5 * time.Second, 100 * time.Millisecond, 5 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := New("127.0.0.1:1", WithBackoff(c.min, c.max))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer w.Close()
			if w.minBackoff != c.wantMin || w.maxBackoff != c.wantMax {
				t.Fatalf("退避参数不符: 得到 min=%v max=%v, 期望 min=%v max=%v",
					w.minBackoff, w.maxBackoff, c.wantMin, c.wantMax)
			}
		})
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
	// 保存并还原全局默认 handler：glog.SetDefaultHandler 改的是包级
	// 全局状态，不还原会泄漏到后续测试——未来新增依赖 glog 默认行为
	// 的测试会意外把日志发往本测试的 TCP receiver。
	oldHandler := glog.GetDefaultHandler()
	t.Cleanup(func() { glog.SetDefaultHandler(oldHandler) })
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

	// 服务器不可达：消息应留队缓冲，等待重连成功后补发。
	if _, err := w.Write([]byte("buffered message")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// 在同一端口把服务端拉起来，Writer 必须能自动重连并补发积压消息。
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
	// 队列 FIFO：宕机期间缓冲的消息先被补发，随后是新消息。
	if got := r.next(t, 3*time.Second); got != "buffered message" {
		t.Fatalf("补发消息不符合预期: %q", got)
	}
	if got := r.next(t, 3*time.Second); got != "recovered message" {
		t.Fatalf("帧不符合预期: %q", got)
	}
	if stats := w.Stats(); stats.Sent != 2 || stats.Dropped != 0 {
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

// TestReceiverRejectsOversizedFrame 验证接收端对损坏/恶意帧的防御：
// 帧长度声明超过 maxFrameLen 时必须直接断开连接，而不是按声明值
// make 巨大缓冲（例如 n=1073741824 会立刻分配 1GB）。
func TestReceiverRejectsOversizedFrame(t *testing.T) {
	r := startReceiver(t)
	conn, err := net.Dial("tcp", r.addr())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	// 声明一条 1GB 的帧并只发送长度前缀。
	if _, err := conn.Write([]byte("1073741824 ")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 接收端识别出超限长度后应关闭连接：读到 EOF（带超时兜底）。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	for {
		if _, err := conn.Read(buf); err != nil {
			break // EOF 或连接错误都表示已断开
		}
	}
	// 不应当有任何帧被投递出来。
	select {
	case f := <-r.frames:
		t.Fatalf("超限帧不应产生消息，却收到: %q", f)
	default:
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

// TestBatchBufferedWhenServerDown 验证批处理模式下服务器不可达时，消息
// 留在队列中缓冲而不是被立即丢弃；Close 的关机路径不做重连等待，尽力
// 一次失败后才整批计入丢弃。
func TestBatchBufferedWhenServerDown(t *testing.T) {
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
		if _, err := w.Write([]byte("buffered batch")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// 覆盖若干轮退避重试，期间消息必须留在队列中，不产生任何丢弃。
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if stats := w.Stats(); stats.Dropped != 0 {
			t.Fatalf("服务器不可达时消息应留队缓冲，却被丢弃: %+v", stats)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stats := w.Stats(); stats.Queued != 3 {
		t.Fatalf("消息应留在队列中缓冲: %+v", stats)
	}
	// Close 尽力一次：连接不可用则整批计入丢弃。
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if stats := w.Stats(); stats.Dropped != 3 || stats.Sent != 0 {
		t.Fatalf("计数不符合预期: %+v", stats)
	}
}
