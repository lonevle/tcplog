// Command example 是一个 GoFrame 演示程序：把应用日志以 IETF Syslog 协议
// （RFC 5424 消息格式 + RFC 6587 八位组计数帧）通过 TCP 发送到远端
// syslog 服务器。
//
// 先启动一个接收端，例如自带的这个：
//
//	go run ./cmd/logrecv -addr 127.0.0.1:6514
//
// 再启动本演示（SYSLOG_ADDR 环境变量可覆盖默认目标地址）：
//
//	go run ./example
//	curl 127.0.0.1:8199/ping
//	curl 127.0.0.1:8199/log
package main

import (
	"log"
	"os"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"

	"github.com/lonevle/tcplog"
)

func main() {
	ctx := gctx.New()

	// syslog 服务器地址（host:port）。6514 是 syslog-over-TCP 的注册
	// 端口，514 也常用于明文 TCP。
	syslogAddr := os.Getenv("SYSLOG_ADDR")
	if syslogAddr == "" {
		syslogAddr = "127.0.0.1:6514"
	}

	// 创建 TCP syslog 发送器。连接是懒建立的，因此即使接收端没启动，
	// 演示程序也能正常起来；消息先缓冲，接收端恢复后自动补发
	// （可用 w.Stats() 观测）。
	w, err := tcplog.New(syslogAddr,
		tcplog.WithQueueSize(8192),
		tcplog.WithErrorHandler(func(err error) {
			// 这里可以接入监控打点，注意不要阻塞。刻意用标准库 log
			// 而不是 glog：glog 已被下面的 handler 路由到同一个 syslog
			// Writer，若在这里用 glog 记录传输错误，服务器宕机期间会
			// 形成自我反馈回路——每轮拨号失败都自产一条 debug 日志
			// 入队，挤占队列、挤掉真正的业务日志。
			log.Printf("syslog 传输错误: %v", err)
		}),
	)
	if err != nil {
		glog.Fatal(ctx, err)
	}
	// Close 会把队列里剩余的消息发完。放在 server 启动前注册，
	// SIGINT/SIGTERM 关机时也会执行到。
	defer w.Close()

	// 自定义 syslog 头部字段（HOSTNAME / APP-NAME / PROCID / facility）。
	formatter := tcplog.DefaultFormatter()
	formatter.AppName = "gf-demo"
	formatter.Facility = tcplog.FacilityLocal0

	// 把所有 GoFrame 日志都路由到 syslog 服务器。handler 会延续 glog
	// 的中间件链，控制台输出仍按日志配置执行。只想发 TCP 的话：
	//	glog.SetConfig(glog.Config{StdoutPrint: false})
	glog.SetDefaultHandler(tcplog.NewGlogHandler(w, formatter))

	glog.Info(ctx, "syslog 发送器就绪, server=", syslogAddr, " queue=", w.Stats().Queued)

	// 一个普通的 GoFrame HTTP 服务，它的请求日志同样会流经上面注册的
	// handler。
	s := g.Server("gf-demo")
	s.SetPort(8199)
	s.BindHandler("/ping", func(r *ghttp.Request) {
		r.Response.Write("pong")
	})
	s.BindHandler("/log", func(r *ghttp.Request) {
		glog.Infof(r.Context(), "handling /log from %s", r.GetClientIp())
		glog.Errorf(r.Context(), "demo error with 中文: code=%d", 500)
		r.Response.Write("logged")
	})
	s.Run()
}
