# 本机监控代理（待真实浏览器验收）

`tools/monitor-loopback-proxy.py` 仅在可信操作员电脑监听 `127.0.0.1:8080`。
它不是服务端认证替代品：浏览器仍需 Apache Basic 认证，服务器的三个 CGI
Host/Origin 门禁不变。代理先严格验证本机请求来源，再为固定服务 IPv4 构建上游请求。
该脚本保留在公开源码及测试治理中，但精确排除于生产 upload、code sync 和 Docker 镜像。

先停止原占用 8080 的 `ssh -L`，确认本机没有其他服务使用该浏览器 origin。
在**本机**、当前已验证的仓库中启动（不要在管理服务器运行）：

```bash
python3 tools/monitor-loopback-proxy.py \
  --service-ip 10.43.40.173 \
  --bastion ubuntu@worker-f6270acf.inside.dsx-air.nvidia.com \
  --ssh-port 29789
```

然后打开 `http://127.0.0.1:8080/monitor/monitor.html`，按原流程登录。
SSH 密钥和 known_hosts 必须已经通过正常操作流程配置；代理使用 BatchMode 和
StrictHostKeyChecking，不交互接受新主机、不保存密码、不启动远端 shell。
每个 HTTP 请求使用一次 SSH `-W 固定服务IP:80`，不监听第二个转发端口，
不自动重试 POST；频繁轮询会增加 SSH 握手开销。Ctrl-C 停止代理。

## 边界

- 仅支持页面、三个 `/monitor/control/` 路由及 `99-output-p2p/` 下安全
  ASCII basename（允许规范 `%20` 表示文件名中的空格）的 `.html` / `.xlsx`
  只读资源。不是通用反向代理；其他资源拒绝。
- POST 要求精确本机 Host、Origin、现代浏览器 `Sec-Fetch-Site: same-origin`、
  对应 X-Requested-With、form 类型、明确有界长度和 Basic 认证。不会自动跳转。
- 请求体上限 64 KiB，响应上限 16 MiB，单次上游期限 30 秒，最多 8 个并发 SSH。
  严格响应解析拒绝重定向、模糊长度、压缩、chunk trailer 和不完整响应。
- 本地拒绝显示“请求未发送”；上游传输/响应失败显示“提交结果未知”。后者不能
  推断操作未执行：先查状态，不要自动重试。完整服务器拒绝保持其 HTTP 状态。
- 不记录访问日志、Basic、请求体或 SSH stderr；不写配置或服务状态。
  真实控制 POST 本身仍可能有设备副作用，仅由操作员按既有授权执行。
- 信任本机账户、SSH 客户端配置、既有 SSH 密钥/主机信任和跳板至服务器的 HTTP
  网络。它不能抵御已控制本机同 UID 的进程、恶意 SSH 配置、浏览器扩展或目标页面 XSS。
  使用专用可信浏览器环境，退出后关闭页面，不要在此 origin 运行不可信应用。

自动化测试只使用合成凭据、本机 fixture 与原 CGI guard；真实 SSH、Apache Basic
挑战及浏览器动作尚须 `TC-REAL-MONITOR-LOOPBACK-PROXY-001` 验收，不能把本机测试
等同部署成功或新的 full proof。
