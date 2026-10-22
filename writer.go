package tcplog

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Writer 的默认参数。
const (
	defaultQueueSize    = 4096
	defaultDialTimeout  = 5 * time.Second
	defaultWriteTimeout = 5 * time.Second
	defaultMinBackoff   = 200 * time.Millisecond
	defaultMaxBackoff   = 10 * time.Second
	defaultBatchSize    = 1 // 1 表示不按条数批处理：每条消息立即发送
)

// ErrClosed 在 Writer 关闭后由 Write 返回。
var ErrClosed = errors.New("tcplog: 发送器已关闭")

// Stats 汇总 Writer 的投递计数，可用于监控。
type Stats struct {
	// Sent 是成功写入 socket 的消息条数。
	Sent uint64

	// Dropped 是被丢弃的消息条数：队列已满、写入 socket 失败，或
	// Close 时连接不可用而放弃的消息。
	Dropped uint64

	// Queued 是当前积压在内存队列中的消息条数。
	Queued int
}

// Writer 把 RFC 5424 syslog 消息通过 TCP 发送到远端服务器，并按
// RFC 6587 添加传输帧。
//
// Writer 可并发使用，且实现了 io.Writer：每次 Write 调用视为一条完整
// 的 syslog 消息（通常是 Formatter.Format 的输出）。投递是异步的——
// Write 只把加帧后的消息放入队列，由后台 goroutine 维护 TCP 连接。
// 服务器不可达时按指数退避重连，期间消息在队列中缓冲，重连成功后
// 自动补发；仅当队列溢出，或单条消息写入 socket 失败（帧边界已破坏）
// 时才会丢包并计数，可通过 Stats 观测。
//
// 默认逐条立即发送；也可用 WithBatchSize / WithBatchInterval 开启批
// 处理，把多条消息合并为一次 socket 写入（代价是投递延迟最多增加
// 一个批处理周期）。
//
// 零值不可用，请通过 New 创建。
type Writer struct {
	addr string

	dialTimeout   time.Duration
	writeTimeout  time.Duration
	queueSize     int
	minBackoff    time.Duration
	maxBackoff    time.Duration
	batchSize     int
	batchInterval time.Duration
	octetCounting bool
	tlsConfig     *tls.Config
	onError       func(error)

	dialer net.Dialer

	queue   chan []byte
	stopCh  chan struct{}
	doneCh  chan struct{}
	stopOne sync.Once

	// sendMu 保护 Write 中“收下还是拒绝”的判定与 Close 之间的竞争，
	// 确保被收进队列的消息一定会被 run 消费掉。
	sendMu sync.Mutex
	closed atomic.Bool

	// 以下字段仅由 run goroutine 独占访问。
	conn     net.Conn
	nextDial time.Time
	backoff  time.Duration

	sent    atomic.Uint64
	dropped atomic.Uint64
}

// Option 在构造时配置 Writer。
type Option func(*Writer)

// WithQueueSize 设置服务器不可达或 socket 拥塞时最多缓冲多少条消息，
// 缓冲区满后新消息直接丢弃。默认 4096。
func WithQueueSize(n int) Option {
	return func(w *Writer) {
		if n > 0 {
			w.queueSize = n
		}
	}
}

// WithDialTimeout 设置 TCP/TLS 连接超时。默认 5s。
func WithDialTimeout(d time.Duration) Option {
	return func(w *Writer) {
		if d > 0 {
			w.dialTimeout = d
		}
	}
}

// WithWriteTimeout 设置单次写入的 socket 超时。超过该时间的写入视为
// 失败并触发重连。默认 5s。
func WithWriteTimeout(d time.Duration) Option {
	return func(w *Writer) {
		if d > 0 {
			w.writeTimeout = d
		}
	}
}

// WithBackoff 设置重连退避区间。连接失败后，下一次拨号会推迟当前退避值
// 加 [0, min] 的随机抖动（闭区间，见 scheduleBackoff）；退避值从 min
// 开始，连续失败时指数翻倍直到 max。默认 200ms / 10s。
//
// 若 max 非正、或小于最终生效的 min，则把 max 兜底提升为 min，保证
// minBackoff <= maxBackoff 恒成立——否则 scheduleBackoff 里的指数增长
// 会因为 backoff >= max 永远不触发，退避被卡死在 min 上，且用户配置
// 的上限被静默丢弃。
func WithBackoff(min, max time.Duration) Option {
	return func(w *Writer) {
		if min > 0 {
			w.minBackoff = min
		}
		if max >= w.minBackoff {
			w.maxBackoff = max
		} else {
			// max 非法（非正，或小于最终 min）：兜底提升到 min，
			// 维持 minBackoff <= maxBackoff 不变式。
			w.maxBackoff = w.minBackoff
		}
	}
}

// WithBatchSize 启用按条数批处理：批内累积到 n 条消息后，合并为一次
// socket 写入，减少 write 系统调用与 TCP 段数量。n 必须 >= 2；默认 1
// （不启用，每条立即发送）。与 WithBatchInterval 同时设置时，任一
// 条件满足即发送。
func WithBatchSize(n int) Option {
	return func(w *Writer) {
		if n >= 2 {
			w.batchSize = n
		}
	}
}

// WithBatchInterval 启用按时间批处理：批内进入第一条消息后开始计时，
// 最多每 d 就把当前批次发送一次（无论是否达到 WithBatchSize 的条数）。
// 与 WithBatchSize 同时设置时，任一条件满足即发送；单独设置时表示
// 纯按时间攒批。默认 0（不启用）。
func WithBatchInterval(d time.Duration) Option {
	return func(w *Writer) {
		if d > 0 {
			w.batchInterval = d
		}
	}
}

// WithLFFraming 选用 RFC 6587 的非透明帧（以 LF 结尾）代替默认的八位组
// 计数帧。仅用于无法解析八位组计数帧的老旧接收端；注意消息内嵌换行会
// 破坏这种帧格式。
func WithLFFraming() Option {
	return func(w *Writer) {
		w.octetCounting = false
	}
}

// WithTLSConfig 开启 syslog over TLS（RFC 5425，通常 6514 端口）。
// 除配置另行指定外，连接默认按系统根证书校验。
func WithTLSConfig(cfg *tls.Config) Option {
	return func(w *Writer) {
		w.tlsConfig = cfg
	}
}

// WithErrorHandler 注册连接/写入错误的回调（例如用来打点），回调不得
// 阻塞。
func WithErrorHandler(f func(error)) Option {
	return func(w *Writer) {
		w.onError = f
	}
}

// New 为 addr（"host:port"）处的 syslog 服务器创建 Writer。
//
// TCP 连接由后台 goroutine 懒建立，因此即使服务器当前不可达，New 也会
// 成功；此期间日志先缓冲在内存中，服务器恢复后自动补发。
func New(addr string, opts ...Option) (*Writer, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("tcplog: 非法的 syslog 服务器地址 %q: %w", addr, err)
	}
	w := &Writer{
		addr:          addr,
		dialTimeout:   defaultDialTimeout,
		writeTimeout:  defaultWriteTimeout,
		queueSize:     defaultQueueSize,
		minBackoff:    defaultMinBackoff,
		maxBackoff:    defaultMaxBackoff,
		batchSize:     defaultBatchSize,
		octetCounting: true,
	}
	for _, o := range opts {
		o(w)
	}
	w.dialer = net.Dialer{Timeout: w.dialTimeout}
	w.queue = make(chan []byte, w.queueSize)
	w.stopCh = make(chan struct{})
	w.doneCh = make(chan struct{})
	go w.run()
	return w, nil
}

// Addr 返回配置的 syslog 服务器地址。
func (w *Writer) Addr() string { return w.addr }

// Write 实现 io.Writer，把 p 视为一条完整的 syslog 消息（例如
// Formatter.Format 的输出），按 RFC 6587 加帧后入队等待异步投递。
//
// Write 绝不会因网络阻塞，避免慢速或宕机的日志服务器拖慢业务日志调用。
// 队列已满时消息会被丢弃并计数（见 Stats），但 Write 仍返回成功。
// Close 之后 Write 返回 ErrClosed。
func (w *Writer) Write(p []byte) (int, error) {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()
	if w.closed.Load() {
		return 0, ErrClosed
	}
	select {
	case w.queue <- w.frame(p):
		return len(p), nil
	default:
		w.dropped.Add(1)
		return len(p), nil
	}
}

// Stats 返回当前投递计数。
func (w *Writer) Stats() Stats {
	return Stats{
		Sent:    w.sent.Load(),
		Dropped: w.dropped.Load(),
		Queued:  len(w.queue),
	}
}

// Close 尽力把队列里剩余的消息发完，然后关闭 TCP 连接。它会阻塞到后台
// goroutine 退出为止。Close 可重复调用。
func (w *Writer) Close() error {
	w.stopOne.Do(func() {
		w.sendMu.Lock()
		w.closed.Store(true)
		w.sendMu.Unlock()
		close(w.stopCh)
	})
	<-w.doneCh
	w.closeConn()
	return nil
}

// frame 对一条 syslog 消息应用 RFC 6587 帧格式。八位组计数（默认的推荐
// 方式）在消息前加“八位组长度 + 空格”；非透明帧则以 LF 结尾。输入缓冲
// 始终被复制，调用方可以自行复用缓冲区。
func (w *Writer) frame(p []byte) []byte {
	if w.octetCounting {
		out := make([]byte, 0, len(p)+12)
		out = strconv.AppendInt(out, int64(len(p)), 10)
		out = append(out, ' ')
		return append(out, p...)
	}
	out := make([]byte, 0, len(p)+1)
	out = append(out, p...)
	return append(out, '\n')
}

// run 是发送 goroutine：持续消费队列并维护 TCP 连接。未启用批处理时
// 走逐条发送路径；启用了 WithBatchSize / WithBatchInterval 任一选项时
// 走批处理路径。
//
// 连接未就绪时 run 不会从队列取消息，而是先阻塞在 ensureConnected 上
// 等待重连成功，让消息在队列中缓冲，服务器恢复后自动补发。
func (w *Writer) run() {
	defer close(w.doneCh)
	if w.batchSize > 1 || w.batchInterval > 0 {
		w.runBatched()
		return
	}
	for {
		// 先确保连接可用再消费队列：服务器不可达期间消息留队缓冲，
		// 由 Write 端按队列容量决定是否丢弃。stopCh 关闭则转入关机清理。
		if !w.ensureConnected() {
			w.drain()
			return
		}
		select {
		case msg := <-w.queue:
			w.deliver(msg)
		case <-w.stopCh:
			w.drain()
			return
		}
	}
}

// drain 是关机路径：把队列里剩余的消息尽力发出。连接可用则逐条发送；
// 不可用且处于退避窗口时直接丢弃（deliver 内的检查会命中）。不在退避
// 窗口时 deliver 仍会尝试一次拨号，因此 Close 最坏可能阻塞一个拨号
// 超时（见 WithDialTimeout），这是“尽力发完”语义的代价。
// 只允许 run goroutine 调用。
func (w *Writer) drain() {
	for {
		select {
		case msg := <-w.queue:
			w.deliver(msg)
		default:
			w.closeConn()
			return
		}
	}
}

// ensureConnected 阻塞到 TCP 连接可用为止：处于退避窗口时先等窗口到期，
// 拨号失败则按指数退避继续重试。期间不消费队列，消息得以在队列中缓冲、
// 服务器恢复后自动补发。stopCh 关闭后返回 false（不再等待、也不再拨号）。
// 只允许 run goroutine 调用。
func (w *Writer) ensureConnected() bool {
	for w.conn == nil {
		if d := time.Until(w.nextDial); d > 0 {
			// 用 NewTimer 并在退出路径显式 Stop，而不是每次循环
			// time.After 新建：避免高频退避期间累积未到期的 timer。
			t := time.NewTimer(d)
			select {
			case <-t.C:
			case <-w.stopCh:
				t.Stop()
				return false
			}
			continue
		}
		if err := w.ensureConn(); err != nil {
			w.emitError(err)
			w.scheduleBackoff()
			continue
		}
	}
	return true
}

// runBatched 是批处理模式下的发送循环：连接未就绪时先等待重连（消息
// 留在队列缓冲），连接就绪后消息在批内累积，满足条数（WithBatchSize）
// 或时间（WithBatchInterval）条件即合并为一次写入。合并只影响 socket
// 写入方式，帧格式不变，接收端仍逐条解析。
func (w *Writer) runBatched() {
	var (
		batch  [][]byte
		timer  *time.Timer
		timerC <-chan time.Time
	)
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			// 已经触发过：把通道里残留的触发值取干净，避免影响下一批。
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerC = nil
	}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.deliverBatch(batch)
		// deliverBatch 已同步拷贝完批次内容，此处可安全复用底层数组。
		batch = batch[:0]
		stopTimer()
	}
	// drainBatched 是关机路径：把队列里剩余的消息尽量按批发完，最后
	// flush 兜底。与逐条模式的 drain 相同，不做重连等待，发不出去的
	// 随批次计入丢弃，保证 Close 快速返回。
	drainBatched := func() {
		for {
			select {
			case msg := <-w.queue:
				batch = append(batch, msg)
				if w.batchSize > 1 && len(batch) >= w.batchSize {
					flush()
				}
			default:
				flush()
				w.closeConn()
				return
			}
		}
	}
	for {
		// 先确保连接可用再消费队列：服务器不可达期间消息留队缓冲。
		if !w.ensureConnected() {
			drainBatched()
			return
		}
		select {
		case msg := <-w.queue:
			batch = append(batch, msg)
			switch {
			case w.batchSize > 1 && len(batch) >= w.batchSize:
				flush()
			case timer == nil && w.batchInterval > 0:
				timer = time.NewTimer(w.batchInterval)
				timerC = timer.C
			}
		case <-timerC:
			flush()
		case <-w.stopCh:
			drainBatched()
			return
		}
	}
}

// deliver 发送一条加帧后的消息。正常路径下连接已由 ensureConnected 保障
// 就绪；写入失败视为连接级故障，丢弃该消息并触发重连退避（TCP 流一旦
// 部分写入，帧边界即被破坏，无法安全重发）。关机 drain 路径下，若处于
// 退避窗口则直接丢弃，否则仍会尝试一次拨号（见 drain 的注释）。
// 只允许 run goroutine 调用。
func (w *Writer) deliver(msg []byte) {
	if w.conn == nil && time.Now().Before(w.nextDial) {
		// 仍处于重连退避窗口内：直接丢弃，避免频繁拨号冲击服务器。
		w.dropped.Add(1)
		return
	}
	if err := w.ensureConn(); err != nil {
		w.emitError(err)
		w.scheduleBackoff()
		w.dropped.Add(1)
		return
	}
	if err := w.writeMsg(msg); err != nil {
		w.closeConn()
		w.emitError(err)
		w.scheduleBackoff()
		w.dropped.Add(1)
		return
	}
	w.sent.Add(1)
	w.backoff = 0 // 投递成功，重置退避
}

// deliverBatch 把一批加帧后的消息合并为一次 socket 写入，减少 write
// 系统调用与 TCP 段数量。合并缓冲区的上限约为 条数 × 单条大小，由
// WithBatchSize 的使用方自行评估内存。整批的投递结果按每条消息计数
// （成功/丢弃都是 len(msgs) 条）。与 deliver 相同：正常路径连接已就绪，
// 关机 drain 路径下若处于退避窗口则整批丢弃。只允许 run goroutine 调用。
func (w *Writer) deliverBatch(msgs [][]byte) {
	if len(msgs) == 0 {
		return
	}
	if w.conn == nil && time.Now().Before(w.nextDial) {
		// 仍处于重连退避窗口内：整批丢弃，避免频繁拨号冲击服务器。
		w.dropped.Add(uint64(len(msgs)))
		return
	}
	if err := w.ensureConn(); err != nil {
		w.emitError(err)
		w.scheduleBackoff()
		w.dropped.Add(uint64(len(msgs)))
		return
	}
	total := 0
	for _, m := range msgs {
		total += len(m)
	}
	buf := make([]byte, 0, total)
	for _, m := range msgs {
		buf = append(buf, m...)
	}
	if err := w.writeMsg(buf); err != nil {
		w.closeConn()
		w.emitError(err)
		w.scheduleBackoff()
		w.dropped.Add(uint64(len(msgs)))
		return
	}
	w.sent.Add(uint64(len(msgs)))
	w.backoff = 0 // 投递成功，重置退避
}

// ensureConn 返回一条可用连接，需要时懒拨号。
func (w *Writer) ensureConn() error {
	if w.conn != nil {
		return nil
	}
	var (
		c   net.Conn
		err error
	)
	if w.tlsConfig != nil {
		c, err = tls.DialWithDialer(&w.dialer, "tcp", w.addr, w.tlsConfig)
	} else {
		c, err = w.dialer.Dial("tcp", w.addr)
	}
	if err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	w.conn = c
	return nil
}

// writeMsg 在写超时约束下写入一条加帧后的消息。
func (w *Writer) writeMsg(msg []byte) error {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout)); err != nil {
		return err
	}
	_, err := w.conn.Write(msg)
	return err
}

// closeConn 拆除当前连接（如有）。
func (w *Writer) closeConn() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// scheduleBackoff 在连接失败后推迟下一次拨号：等待时长为当前退避值加
// [0, min] 的随机抖动，避免多实例同时重连造成惊群。退避值从 min 起
// 指数翻倍、封顶 max；任何一次投递成功后清零（见 deliver/deliverBatch）。
func (w *Writer) scheduleBackoff() {
	switch {
	case w.backoff == 0:
		w.backoff = w.minBackoff
	case w.backoff < w.maxBackoff:
		w.backoff *= 2
		if w.backoff > w.maxBackoff {
			w.backoff = w.maxBackoff
		}
	}
	// 加抖动，避免多实例同时重连造成惊群。rand.Int64N(n) 返回 [0, n)，
	// 传入 min+1 即得 [0, min]（整数闭区间）。
	jitter := time.Duration(rand.Int64N(int64(w.minBackoff) + 1))
	w.nextDial = time.Now().Add(w.backoff + jitter)
}

// emitError 把传输错误上报给已注册的错误回调（如有）。
func (w *Writer) emitError(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}
