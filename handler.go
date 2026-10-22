// Package tcplog 把 GoFrame（glog）应用的日志以 IETF Syslog 协议通过
// TCP 发送到远端日志服务器，适用于对接 syslog-ng、rsyslog、Fluent Bit、
// Logstash、SIEM 等采集端。
//
// 消息格式遵循 RFC 5424，传输帧默认采用 RFC 6587 八位组计数方式，
// 可选 RFC 5425 TLS 加密。基本用法：
//
//	w, err := tcplog.Setup("127.0.0.1:6514", nil)
//	if err != nil {
//		panic(err)
//	}
//	defer w.Close()
//
// 之后所有 glog 调用都会发往 syslog 服务器。详细说明见仓库 README。
package tcplog

import (
	"context"
	"io"

	"github.com/gogf/gf/v2/os/glog"
)

// glogLevelToSeverity 把 GoFrame 日志级别映射为 RFC 5424 严重级别。
var glogLevelToSeverity = map[int]int{
	glog.LEVEL_DEBU: SeverityDebug,
	glog.LEVEL_INFO: SeverityInformational,
	glog.LEVEL_NOTI: SeverityNotice,
	glog.LEVEL_WARN: SeverityWarning,
	glog.LEVEL_ERRO: SeverityError,
	glog.LEVEL_CRIT: SeverityCritical,
	glog.LEVEL_PANI: SeverityAlert,
	glog.LEVEL_FATA: SeverityEmergency,
}

// SeverityFromGlogLevel 把 GoFrame glog 级别常量映射为对应的 RFC 5424
// 严重级别；未知级别按 Informational 处理。
func SeverityFromGlogLevel(level int) int {
	if severity, ok := glogLevelToSeverity[level]; ok {
		return severity
	}
	return SeverityInformational
}

// NewGlogHandler 返回一个 glog.Handler，把每条日志以 RFC 5424 消息发给
// w。w 通常是 *Writer，但任何 io.Writer 都可以（例如测试里用
// bytes.Buffer）。formatter 传 nil 时使用 DefaultFormatter。
//
// GoFrame 日志字段到 syslog 字段的映射关系：
//
//	Time            -> TIMESTAMP
//	Level           -> PRI（严重级别）与 MSGID
//	TraceId         -> STRUCTURED-DATA [goframe trace="..."]
//	CtxStr          -> STRUCTURED-DATA [goframe ctx="..."]
//	Prefix          -> STRUCTURED-DATA [goframe prefix="..."]
//	CallerPath      -> STRUCTURED-DATA [goframe caller="..."]
//	Content+Values  -> MSG（如有 Stack 则追加到 MSG 末尾）
//
// 注册到包级 logger：
//
//	glog.SetDefaultHandler(tcplog.NewGlogHandler(w, nil))
//
// 或注册到 logger 实例：
//
//	logger := glog.New()
//	logger.SetHandler(tcplog.NewGlogHandler(w, nil))
//
// 本 handler 会通过 HandlerInput.Next 延续 glog 的中间件链，因此内置的
// 最终 handler 仍会按日志配置（glog.Config）执行控制台/文件输出。只想
// 发 TCP 时，配置 StdoutPrint: false 且不设文件 Path 即可。
func NewGlogHandler(w io.Writer, formatter *Formatter) glog.Handler {
	if formatter == nil {
		formatter = DefaultFormatter()
	}
	return func(ctx context.Context, in *glog.HandlerInput) {
		// 投递是异步且允许丢包的，这是刻意设计：handler 绝不能阻塞或
		// 让日志调用失败，因此这里忽略写入错误。
		_, _ = w.Write(formatter.Format(&Record{
			Time:     in.Time,
			Severity: SeverityFromGlogLevel(in.Level),
			MsgID:    in.LevelFormat,
			Msg:      messageContent(in),
			SD:       structuredData(in),
		}))
		// glog 的多个 handler 组成一条中间件链，链尾是负责控制台/文件
		// 输出的内置最终 handler。继续往下走，输出行为就仍然由日志配置
		// 决定；若配置里关掉了 stdout 又没配文件路径，这里就是空操作。
		in.Next(ctx)
	}
}

// Setup 是 New + NewGlogHandler 的便捷封装：为 addr 创建 Writer 并注册
// 为 glog 默认 handler，这样所有 GoFrame 日志都会发往 syslog 服务器。
// 关闭时调用返回 writer 的 Close 以flush 剩余消息。
//
// formatter 传 nil 时使用 DefaultFormatter。
func Setup(addr string, formatter *Formatter, opts ...Option) (*Writer, error) {
	w, err := New(addr, opts...)
	if err != nil {
		return nil, err
	}
	glog.SetDefaultHandler(NewGlogHandler(w, formatter))
	return w, nil
}

// messageContent 从 GoFrame handler 输入拼出 syslog 的 MSG：原始内容、
// 传入的值，以及堆栈（如有）。
func messageContent(in *glog.HandlerInput) string {
	content := in.Content
	if values := in.ValuesContent(); values != "" {
		if content == "" {
			content = values
		} else {
			content += " " + values
		}
	}
	if in.Stack != "" {
		content += "\nStack:\n" + in.Stack
	}
	return content
}

// structuredData 把 GoFrame 日志元数据映射为一个 RFC 5424
// STRUCTURED-DATA 元素。
func structuredData(in *glog.HandlerInput) []SDElement {
	params := make([]SDParam, 0, 5)
	params = append(params, SDParam{Key: "level", Value: in.LevelFormat})
	if in.TraceId != "" {
		params = append(params, SDParam{Key: "trace", Value: in.TraceId})
	}
	if in.CtxStr != "" {
		params = append(params, SDParam{Key: "ctx", Value: in.CtxStr})
	}
	if in.Prefix != "" {
		params = append(params, SDParam{Key: "prefix", Value: in.Prefix})
	}
	if in.CallerPath != "" {
		params = append(params, SDParam{Key: "caller", Value: in.CallerPath})
	}
	return []SDElement{{ID: "goframe", Params: params}}
}
