# Changelog

## [0.1.0](https://github.com/lonevle/tcplog/compare/v0.0.1...v0.1.0) (2026-10-22)


### 🚀 Features

* 增强 syslog 消息格式化和错误处理，添加非 ASCII 字符检查 ([af5dbf6](https://github.com/lonevle/tcplog/commit/af5dbf650b501fcaf280a0e2f3bedda8ad3e091f))
* 添加 syslog 帧长度限制，增强对损坏帧的防御；优化 SD-ID 和 SD-PARAM-NAME 的清洗逻辑 ([a9faaa1](https://github.com/lonevle/tcplog/commit/a9faaa1d55106537323f9e7931d0961eada65c23))


### 🐛 Bug Fixes

* 增加对帧长度前缀的限制，防止损坏流导致内存耗尽；更新测试用例以验证防御机制 ([8a99ca6](https://github.com/lonevle/tcplog/commit/8a99ca6d6884287b1715a4878ba83b283b25be3a))
* 更新测试用例以验证消息缓冲和重连机制 ([1393f3e](https://github.com/lonevle/tcplog/commit/1393f3e18198694b4952c898e09b52c67599d185))
