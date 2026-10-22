package tcplog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// IETF Syslog 协议常量（RFC 5424）。
const (
	// Version 是 SYSLOG 协议版本号（RFC 5424 第 6.2.2 节）。
	Version = 1

	// NilValue 表示字段缺失，即 "-"。
	NilValue = "-"
)

// Syslog 严重级别（Severity）取值，数值越小越严重（RFC 5424 第 6.2.1 节）。
const (
	SeverityEmergency     = 0 // 系统不可用
	SeverityAlert         = 1 // 必须立即处理
	SeverityCritical      = 2 // 严重故障
	SeverityError         = 3 // 错误
	SeverityWarning       = 4 // 警告
	SeverityNotice        = 5 // 正常但值得注意的事件
	SeverityInformational = 6 // 一般信息
	SeverityDebug         = 7 // 调试信息
)

// 常用 Syslog 设备类型（Facility）取值（RFC 5424 第 6.2.1 节）。
const (
	FacilityKern     = 0  // 内核
	FacilityUser     = 1  // 用户级
	FacilityMail     = 2  // 邮件
	FacilityDaemon   = 3  // 守护进程
	FacilityAuth     = 4  // 认证
	FacilitySyslog   = 5  // syslog 自身
	FacilityLpr      = 6  // 打印
	FacilityNews     = 7  // 新闻
	FacilityUucp     = 8  // UUCP
	FacilityClock    = 9  // 时钟
	FacilityAuthpriv = 10 // 安全认证
	FacilityFtp      = 11 // FTP
	FacilityNtp      = 12 // NTP
	FacilityAudit    = 13 // 审计
	FacilityAlert    = 14 // 告警
	FacilityClock2   = 15 // 时钟（第二个）
	FacilityLocal0   = 16 // 本地自定义 0，应用日志的惯例取值
	FacilityLocal1   = 17 // 本地自定义 1
	FacilityLocal2   = 18 // 本地自定义 2
	FacilityLocal3   = 19 // 本地自定义 3
	FacilityLocal4   = 20 // 本地自定义 4
	FacilityLocal5   = 21 // 本地自定义 5
	FacilityLocal6   = 22 // 本地自定义 6
	FacilityLocal7   = 23 // 本地自定义 7
)

// utf8BOM 在开启 Formatter.BOM 时附加到 MSG 之前。个别老旧接收端靠它
// 识别 MSG 是 UTF-8 编码。
const utf8BOM = "\xEF\xBB\xBF"

// Record 是一条待发送的日志记录，渲染为一条 RFC 5424 消息。
type Record struct {
	// Time 是日志事件时间；零值渲染为 NILVALUE。
	Time time.Time

	// Severity 是 syslog 严重级别，取值 0（Emergency）到 7（Debug）。
	Severity int

	// MsgID 标识消息类型，例如 "INFO"；为空、含空白或含非 ASCII 字符
	// 时渲染为 NILVALUE。
	MsgID string

	// Msg 是自由格式的日志内容（UTF-8）。使用八位组计数帧时允许包含
	// 换行；为空时渲染为 NILVALUE。
	Msg string

	// SD 是 STRUCTURED-DATA 元素列表；为空时该字段渲染为 NILVALUE。
	SD []SDElement
}

// SDParam 是 SDElement 中的一组 SD-PARAM（键值对）。
type SDParam struct {
	Key   string
	Value string
}

// SDElement 是一个 STRUCTURED-DATA 元素，形如 [SD-ID 参数="值" ...]。
type SDElement struct {
	ID     string
	Params []SDParam
}

// String 渲染整个元素，并按 RFC 5424 第 6.3.3 节转义参数值
// （字符 '"'、'\'、']' 必须转义）。
func (sd SDElement) String() string {
	var buf strings.Builder
	buf.WriteByte('[')
	buf.WriteString(sanitizeSDName(sd.ID, "elem"))
	for _, p := range sd.Params {
		buf.WriteByte(' ')
		buf.WriteString(sanitizeSDName(p.Key, "param"))
		buf.WriteString(`="`)
		buf.WriteString(escapeSDValue(p.Value))
		buf.WriteByte('"')
	}
	buf.WriteByte(']')
	return buf.String()
}

// Formatter 把 Record 渲染为 RFC 5424 SYSLOG 消息，其字段承载进程级
// 静态的 HEADER 字段。一般直接用 DefaultFormatter 取默认值，也可以
// 手动填充结构体。
type Formatter struct {
	// Hostname 对应 HOSTNAME 字段；为空、含空白或含非 ASCII 字符时
	// 渲染为 NILVALUE。
	Hostname string

	// AppName 对应 APP-NAME 字段；为空、含空白或含非 ASCII 字符时
	// 渲染为 NILVALUE。
	AppName string

	// ProcID 对应 PROCID 字段；为空、含空白或含非 ASCII 字符时
	// 渲染为 NILVALUE。
	ProcID string

	// Facility 是 syslog 设备类型，取值 0-23，超出范围会被截断到边界值。
	// 默认为 FacilityLocal0（16）。
	Facility int

	// BOM 控制是否在 MSG 前附加 UTF-8 BOM，仅在接收端无法识别 UTF-8
	// 内容时才需要开启。
	BOM bool
}

// DefaultFormatter 返回一个填充了合理默认值的 Formatter：用
// os.Hostname() 取主机名、可执行文件名作为 APP-NAME、当前 PID，
// facility 取 local0（应用日志的惯例取值）。
func DefaultFormatter() *Formatter {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	appName := ""
	if len(os.Args) > 0 && os.Args[0] != "" {
		appName = filepath.Base(os.Args[0])
	}
	return &Formatter{
		Hostname: hostname,
		AppName:  appName,
		ProcID:   strconv.Itoa(os.Getpid()),
		Facility: FacilityLocal0,
	}
}

// Format 把 r 渲染为一条完整的 RFC 5424 SYSLOG 消息，不带任何传输帧
// （RFC 6587 帧由 Writer 负责添加）。
func (f *Formatter) Format(r *Record) []byte {
	pri := clamp(f.Facility, 0, 23)*8 + clamp(r.Severity, 0, 7)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "<%d>%d %s %s %s %s %s ", pri, Version,
		formatTimestamp(r.Time),
		headerValue(f.Hostname),
		headerValue(f.AppName),
		headerValue(f.ProcID),
		headerValue(r.MsgID),
	)
	// STRUCTURED-DATA 字段
	if len(r.SD) == 0 {
		buf.WriteString(NilValue)
	} else {
		for _, sd := range r.SD {
			buf.WriteString(sd.String())
		}
	}
	buf.WriteByte(' ')
	// MSG 字段
	switch {
	case r.Msg == "":
		buf.WriteString(NilValue)
	case f.BOM:
		buf.WriteString(utf8BOM)
		buf.WriteString(r.Msg)
	default:
		buf.WriteString(r.Msg)
	}
	return buf.Bytes()
}

// formatTimestamp 按 RFC 5424 TIMESTAMP 要求渲染时间：RFC 3339 且必须
// 带数字时区偏移。这里刻意不用 "Z"，以兼容更多接收端实现。
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return NilValue
	}
	return t.Format("2006-01-02T15:04:05.000000-07:00")
}

// headerValue 清洗 HEADER 字段：RFC 5424 要求 HOSTNAME / APP-NAME /
// PROCID / MSGID 只能由不含空格的可打印 US-ASCII（0x21-0x7E）组成。
// 因此空值，或含空白及其他控制字符、DEL、任何非 ASCII 字节（例如中文
// 主机名的 UTF-8 编码）的值，一律整体替换为 NILVALUE，避免产出会被
// 严格接收端拒收的非法帧。
func headerValue(s string) string {
	if s == "" {
		return NilValue
	}
	for i := 0; i < len(s); i++ {
		// c <= 0x20 覆盖空格与所有控制字符（含 \t\r\n），
		// c >= 0x7F 覆盖 DEL 以及 UTF-8 多字节序列的所有字节。
		if c := s[i]; c <= 0x20 || c >= 0x7F {
			return NilValue
		}
	}
	return s
}

// sanitizeSDName 清洗 SD-ID 与 SD-PARAM-NAME：只允许除 '='、空格、']'、
// '"' 之外的可打印 ASCII（RFC 5424 第 6.3 节），非法字符替换为 '_'。
// 空值替换为 fallback——RFC 要求两者非空且语义不同：SD-ID 是元素名，
// 传 "elem"；SD-PARAM-NAME 是参数名，传 "param"。
func sanitizeSDName(s, fallback string) string {
	if s == "" {
		return fallback
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' || c == ' ' || c == ']' || c == '"' || c < 0x21 || c > 0x7E {
			sb.WriteByte('_')
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// sdValueEscaper 是预编译的 SD-PARAM 值转义器。strings.Replacer 构建
// 时会编译内部的匹配结构，且文档保证其可并发使用——escapeSDValue 位于
// 每条日志的热路径上，每次调用都 NewReplacer 意味着每条消息的每个
// SD 参数都重复编译一遍，因此提为包级只编译一次。
var sdValueEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`]`, `\]`,
)

// escapeSDValue 按 RFC 5424 第 6.3.3 节转义 SD-PARAM 的值。
func escapeSDValue(s string) string {
	return sdValueEscaper.Replace(s)
}

// clamp 把 v 限制在 [min, max] 区间内。
func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
