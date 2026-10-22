# GoFrame IETF Syslog over TCP 日志发送组件

```go
import "github.com/lonevle/tcplog"
```

让 GoFrame（glog）应用把日志以 **IETF Syslog 协议** 通过 **TCP** 发送到远端日志服务器，适用于对接 syslog-ng、rsyslog、Fluent Bit、Logstash、SIEM 等采集端。

- 消息格式：[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)（IETF Syslog）
- 传输帧格式：[RFC 6587](https://datatracker.ietf.org/doc/html/rfc6587) 八位组计数（默认），兼容 LF 非透明帧
- 可选加密：[RFC 5425](https://datatracker.ietf.org/doc/html/rfc5425) TLS（通常 6514 端口）

## 安装

```bash
go get github.com/lonevle/tcplog
```

## 功能特性

- **零侵入接入**：注册一个 glog handler，所有 GoFrame 日志（`glog.Info`、`glog.Error`、`g.Trace`、HTTP server 请求日志等）自动发往 syslog 服务器
- **全异步不阻塞**：日志调用只入内存队列，网络慢/宕机不会拖慢业务
- **断线自动重连**：懒连接 + 指数退避（带抖动），服务器恢复后自动补发队列中的消息
- **可选批处理**：按条数/按时间把多条消息合并为一次 socket 写入，降低高频日志开销（默认关闭）
- **优雅退出**：`Close()` 会把队列里剩余的消息发完再返回
- **可观测**：`Stats()` 提供已发送/已丢弃/积压计数，另有传输错误回调
- **结构化数据**：trace id、调用位置、前缀等信息进 RFC 5424 STRUCTURED-DATA，方便接收端检索

## 报文长什么样

```
<134>1 2026-10-21T12:13:47.924658+08:00 DESKTOP-VET5GLT gf-demo 4120 INFO [goframe level="INFO" trace="d43a..."] handling /log from 127.0.0.1
 └PRI └V  └TIMESTAMP                  └HOSTNAME       └APP    └PID └MSGID └STRUCTURED-DATA                    └MSG
```

- `PRI = Facility × 8 + Severity`，默认 `local0(16)`，INFO(6) 即 `134`
- 时间戳带数字时区偏移（如 `+08:00`），刻意不用 `Z` 以兼容更多接收端
- 中文等 UTF-8 内容原样透传，STRUCTURED-DATA 值按规范转义

## 快速开始（本地联调）

克隆本仓库后，无需任何外部基础设施，用自带的接收端即可验证：

```bash
# 终端 1：启动 syslog TCP 接收端
go run ./cmd/logrecv -addr 127.0.0.1:6514

# 终端 2：启动 GoFrame 演示程序（SYSLOG_ADDR 可覆盖默认目标）
go run ./example

# 终端 3：触发一些日志
curl 127.0.0.1:8199/ping
curl 127.0.0.1:8199/log
```

接收端会逐条打印收到的报文，包括启动日志、路由表、请求日志和错误堆栈。

## 接入自己的 GoFrame 项目

### 方式一：一行 Setup（推荐）

```go
import "github.com/lonevle/tcplog"

func main() {
	w, err := tcplog.Setup("日志服务器IP:6514", nil)
	if err != nil {
		panic(err)
	}
	defer w.Close() // 退出前 flush 剩余消息

	// 之后所有 glog 调用都会发往 syslog 服务器
	glog.Info(ctx, "服务启动")
}
```

### 方式二：显式组装（自定义 syslog 头部字段）

```go
import "github.com/lonevle/tcplog"

w, err := tcplog.New("日志服务器IP:6514", tcplog.WithQueueSize(8192))
if err != nil {
	panic(err)
}
defer w.Close()

f := tcplog.DefaultFormatter()
f.AppName = "order-service"       // APP-NAME
f.Facility = tcplog.FacilityLocal0 // Facility，默认就是 local0

glog.SetDefaultHandler(tcplog.NewGlogHandler(w, f))
```

### 方式三：只给某个 logger 实例使用

```go
logger := glog.New()
logger.SetHandler(tcplog.NewGlogHandler(w, nil))
```

### 只想发 TCP、不要控制台输出

```go
glog.SetConfig(glog.Config{StdoutPrint: false})
```

> handler 会通过 `in.Next(ctx)` 延续 glog 的中间件链，因此默认情况下控制台/文件输出行为完全由 `glog.Config` 决定，TCP 发送是“旁路”，不影响原有日志行为。

## 配置选项

`tcplog.New(addr, opts...)` 支持以下选项：

| 选项 | 说明 | 默认值 |
|---|---|---|
| `WithQueueSize(n)` | 服务器不可达时最多缓冲的消息条数，满则丢包 | 4096 |
| `WithDialTimeout(d)` | TCP/TLS 连接超时 | 5s |
| `WithWriteTimeout(d)` | 单次写入超时，超时视为失败并重连 | 5s |
| `WithBackoff(min, max)` | 重连退避区间（指数增长 + 抖动） | 200ms / 10s |
| `WithBatchSize(n)` | 按条数批处理：批内攒够 n 条合并为一次 socket 写入（n≥2） | 1（关闭，逐条发送） |
| `WithBatchInterval(d)` | 按时间批处理：批内第一条进入后计时，最多每 d 强制发送一次 | 0（关闭） |
| `WithLFFraming()` | 改用 LF 非透明帧（仅用于无法解析八位组计数帧的老接收端） | 关闭 |
| `WithTLSConfig(cfg)` | 开启 syslog over TLS（RFC 5425，6514 端口） | 关闭 |
| `WithErrorHandler(f)` | 传输错误回调，可接入监控打点，不得阻塞 | 无 |

`Formatter` 可定制：`Hostname`、`AppName`、`ProcID`、`Facility`（0–23）、`BOM`（MSG 前加 UTF-8 BOM，老旧接收端才需要）。

## 批处理（可选）

默认逐条立即发送。日志量很大（每秒数千条以上）时，可以开启批处理，把多条消息合并为一次 socket 写入，减少 write 系统调用和 TCP 段数量：

```go
w, err := tcplog.New(addr,
	tcplog.WithBatchSize(100),                      // 攒够 100 条发一批
	tcplog.WithBatchInterval(200*time.Millisecond), // 或最多 200ms 发一批
)
```

- 两个条件独立生效，任一满足即发送；也可以只配一个（纯按条数 / 纯按时间）
- 合并只改变写入方式：每条消息仍带各自的 RFC 6587 帧，接收端逐条解析，报文内容与逐条发送完全一致
- 代价是投递延迟最多增加一个批处理周期；对延迟敏感的告警类日志不建议开
- 合并缓冲区大小约为 `条数 × 单条大小`，注意按单条日志体量评估批大小
- `Close()` 会把当前批次发完再退出；`Stats()` 的 `Sent`/`Dropped` 按消息条数计数，与是否批处理无关

## glog 字段 → syslog 字段映射

| GoFrame 日志字段 | syslog 字段 |
|---|---|
| `Time` | TIMESTAMP |
| `Level` | PRI（严重级别）+ MSGID |
| `Content` + `Values` | MSG |
| `Stack` | 追加到 MSG 末尾 |
| `TraceId` | STRUCTURED-DATA `[goframe trace="..."]` |
| `CtxStr` / `Prefix` / `CallerPath` | STRUCTURED-DATA 对应参数 |

级别映射：`DEBU→7`、`INFO→6`、`NOTI→5`、`WARN→4`、`ERRO→3`、`CRIT→2`、`PANI→1`、`FATA→0`。

## 工作原理与可靠性语义

```
glog.Info(...) ──► NewGlogHandler ──► Formatter.Format (RFC 5424)
                                          │
                                          ▼
                                   Writer.Write ──► 内存队列 (channel)
                                                          │
                                   后台 goroutine ◄───────┘
                                     ├─ 懒连接 / 断线指数退避重连
                                     ├─ RFC 6587 八位组计数加帧
                                     └─ SetWriteDeadline 写入 socket
```

- **发送器启动不依赖日志服务器**：连接懒建立，服务器没起来也能正常启动，消息进队列，恢复后自动补发
- **可能丢包的两种情况**：① 连接不可用且重试失败；② 队列满（默认 4096 条）。两种都计入 `Stats().Dropped`，建议接入监控告警
- **退出时**：`Close()` 先尽力发完队列中的消息，再关闭连接，可重复调用
- **写超时/读失败会触发重连**，不会无限重试同一条消息

## 测试

```bash
go test ./... -v -race
```

覆盖：RFC 5424 格式化（含 NILVALUE、转义、时间戳）、帧格式、端到端收发、glog 集成、懒连接与退避重连、Close flush、关闭后写入、队列溢出丢包、错误回调。

## 常见问题

**Q：日志服务器 IP 怎么配？**
A：演示程序读环境变量 `SYSLOG_ADDR`，默认 `127.0.0.1:6514`；接入时把 `tcplog.Setup` 的地址参数改成你的服务器即可。生产环境建议从配置文件读取。

**Q：514 和 6514 有什么区别？**
A：514 是传统 syslog 端口（TCP/UDP 均可），6514 是 syslog-over-TLS 的注册端口。明文 TCP 用哪个都可以，TLS 用 6514。

**Q：服务器重启期间日志会丢吗？**
A：重启时间短于队列耗尽时间则不丢——消息在内存排队，重连成功后自动补发；队列满（默认 4096 条）后才开始丢，可通过加大 `WithQueueSize` 缓解。

**Q：怎么知道有没有在丢日志？**
A：定期打印 `w.Stats()`，关注 `Dropped` 和 `Queued` 两个指标，`Queued` 持续上涨说明服务器消费不过来。

**Q：接收端报“非法的帧长度”？**
A：对方按 LF 帧解析了八位组计数帧。确认接收端支持 RFC 6587 octet-counting；实在不支持就在发送端加 `WithLFFraming()`（注意消息内嵌换行会破坏 LF 帧）。

**Q：消息太大怎么办？**
A：RFC 6587 建议单条不超过 2048 八位组，部分接收端有 480/2048/8K 等限制。本组件不截断，超限风险由使用方评估；必要时在业务侧缩短单条日志。

**Q：中文乱码？**
A：RFC 5424 的 MSG 是 UTF-8，本组件原样透传。若接收端显示乱码，先确认接收端按 UTF-8 解析，再考虑 `Formatter.BOM`。

## 目录结构

```
├── format.go                # RFC 5424 消息格式化
├── writer.go                # TCP 发送器（RFC 6587 帧、重连、队列）
├── handler.go               # glog handler 接入（包文档）
├── tcplog_test.go           # 测试套件
├── example/main.go          # GoFrame 演示程序（HTTP :8199）
├── cmd/logrecv/main.go      # 独立的 syslog TCP 接收端（联调用）
├── go.mod / go.sum
├── README.md
└── .gitignore
```
