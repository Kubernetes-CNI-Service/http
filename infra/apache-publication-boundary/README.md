# Apache 静态发布边界与信任模型

`infra-setup.sh` 在管理服务器安装
`/etc/apache2/conf-enabled/http-ztp-public-boundary.conf`。它关闭 DocumentRoot 目录枚举，并在
URL 空间中拒绝以下静态读取：

- `DAY0-Prepare/` 项目源码和结果；
- `monitor/status/`、`monitor/ztp-status/`、`ztp/status/`，包括软链接别名；
- DHCP 目录、Cumulus/NVOS template、backup 和 optimize 内部目录；
- 任意位置的 `*.py`、`*.cgi`、Python bytecode、日志、manifest、release 状态、global/devices/
  subnet 输入及 DHCP 配置文件。

以下现有入口不会命中拒绝规则：`monitor/monitor.html`、Cumulus bootstrap、`ztp.json`、项目
公钥、Cumulus/NVOS `latest_yaml`、NVOS hardening 文件、系统镜像、离线 APT 仓库和
`/cgi-bin/` 下三个无扩展名控制入口。infra 先把配置写入临时文件并原子替换，再对完整 Apache
配置执行 `apache2ctl configtest`；失败时恢复本次执行前的文件且不会进入服务 restart。load
还会在服务启动门禁中验证该文件的精确 SHA-256，旧版、缺失或手工漂移的策略必须先重新运行
当前 `infra-setup.sh`。`infra-teardown.sh` 根据 managed-files 恢复原配置或删除工具新建文件。

Apache 的 URL 规则会在任意深度保留 `DAY0-Prepare`、`status`、`backup`、`optimize` 路径段，
以及 `monitor/ztp-status`、`config/isc-dhcp-server`、`config/cumulus/template`、
`config/nvos/template` 连续路径。为避免配置一个注定被 Apache 拒绝的自定义发布入口，
`01-a-setup.py`、`11-load.py`、DHCP 生成器、manual ZTP 和 prefix ownership marker 共用同一
fail-closed 校验：`ztp_url_prefix`（不区分大小写）不得包含上述保留段或序列。默认 `/ztp`
以及 `/custom`、`/nested/public` 等不冲突前缀仍可使用。

## 当前信任模型

这只是静态文件的最小防误发布边界，不是用户认证或传输安全方案。它不会识别 HTTP/CGI
调用者，也没有为 `monitor.html` 或 `/cgi-bin/ztp-monitor-control`、
`switch-collection-control`、`manual-ztp-control` 提供登录、授权、CSRF 防护或 mTLS。CGI 的
固定参数、服务端校验和受限 worker 缩小了操作范围，但不能代替调用者认证；HTTP 上发布的
bootstrap、YAML 和公钥也不是加密通道。

因此当前前提是：只有受信任运维人员和受管设备能够到达管理服务器的 HTTP/HTTPS 监听地址。
不要把该 vhost 暴露到办公网、访客网或 Internet。若存在非信任客户端，需由部署方选择并在
独立受控 vhost/反向代理上配置来源 ACL 与真实认证，优先使用 TLS+mTLS 或组织统一身份系统；
证书颁发、身份映射和允许来源属于环境策略，项目不会假装自动选择或完成它们。加固后仍应保留
本静态边界作为纵深防护。

## 部署后检查

```bash
sudo apache2ctl configtest
sudo sha256sum /etc/apache2/conf-enabled/http-ztp-public-boundary.conf

# 这些应为 200（具体文件必须存在）
curl -fsSI http://127.0.0.1/monitor/monitor.html
curl -fsSI http://127.0.0.1/ztp/ztp.json

# 这些应为 403；不能因为文件不存在而只接受 404 作为边界证据
curl -sSI http://127.0.0.1/DAY0-Prepare/11-load.py
curl -sSI http://127.0.0.1/monitor/status/manual-ztp.status.json
curl -sSI http://127.0.0.1/ztp/config/isc-dhcp-server/dhcpd.conf
```
