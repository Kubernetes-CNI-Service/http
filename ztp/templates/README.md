# ZTP Bootstrap 不可变模板

## 在整体架构中的位置

本目录属于源代码模板层，不能直接作为交换机下载入口。`11-load.py` 根据当前项目版本、升级
策略、服务 IP、URL 前缀和公钥路径渲染两份运行脚本，完成语法/占位门禁后才原子发布到
`ztp/`。公开仓库的边界见 `.github/README.md`；私有工作区如保留 `USER_MANUAL.md`，其中的
“场景四至场景六”说明现场实施流程。

本目录保存 `11-load.py` 渲染 ZTP 运行脚本时使用的公共源模板。

- `ztp.json`：NVOS ZTP 描述文件的 canonical 模板。`load` 会按当前服务地址与 URL prefix
  渲染出运行态 `ztp/ztp.json`。
- 运行态 `ztp-bootstrap_oob.sh`、`ztp-bootstrap_oobofoob.sh` 和 `ztp/ztp.json` 均含站点值，
  不属于版本控制；测试在临时目录中从 canonical 模板渲染并验证它们。

- `ztp-bootstrap.sh`：同时支持 Cumulus Linux 和 NVOS。模板内的 HTTP Server、URL 前缀、
  Cumulus 目标版本、升级策略和公钥路径是安全占位值；load 根据当前项目和 DHCP 服务地址
  渲染为 `ztp/ztp-bootstrap_oob.sh` 与 `ztp/ztp-bootstrap_oobofoob.sh`，再做 Bash 语法和
  未替换占位检查后原子发布。`MANUAL_ZTP_OOB_URL` 与
  `MANUAL_ZTP_OOBOFOOB_URL` 在两份产物中都渲染为当前项目各自的固定 bootstrap URL。
  所有运行日志行统一使用 RFC3339 UTC 时间戳（`YYYY-MM-DDTHH:MM:SSZ`），不受设备在
  YAML apply 前后发生的时区变化影响。

Cumulus bootstrap 结束前安装 `/usr/local/sbin/http-manual-ztp-oob`、
`/usr/local/sbin/http-manual-ztp-oobofoob` 和对应 sudoers 条目。这两个 helper 均由 root
拥有、不接受任何参数，分别只能执行 load 渲染时固定的 OOB/OOBofOOB `ztp -r <URL>`；
调用者不能注入 URL 或 shell 参数。
管理服务器根据设备 eth0 IP 所属 DHCP subnet 选择 helper，不再依赖设备上一次写入的单一
URL。旧 `/usr/local/sbin/http-manual-ztp` 和所有 `http-manual-reset*` helper 会被移除。
手工重置由管理服务器直接以 `cumulus` 用户后台调用固定的
`nv action reset system factory-default force`，不需要 sudoers。sudoers 只允许 `cumulus`
用户无密码执行两个 ZTP helper，不授予通用 `ztp`、`nv`、shell 或任意 sudo 权限。临时文件先
设置 owner/mode，sudoers 通过 `visudo -cf` 后才原子替换。已有设备只有在重新执行一次新版
bootstrap 后才具备网页手工 ZTP 能力；手工重置不依赖这些 helper。

Cumulus 与 NVOS 成功 bootstrap 还会安装 root 拥有、零参数的
`/usr/local/sbin/http-sync-management-time` 和独立 sudoers。该 helper 只轮询 load 已固定渲染的
OOB/OOBofOOB ZTP URL，解析并验证 Apache HTTP `Date` 后设置系统时钟；调用者不能传入时间、
URL、IP 或 shell 参数。管理页面执行后会通过另一次身份校验 SSH 重新测量偏移，因此 helper
退出 0 本身不等同于同步成功。已有设备须重新完成一次新版 bootstrap 才会取得该 helper。

bootstrap 在初始 DHCP 所选网络路径仍可用、且尚未执行任何 `nv config` 变更时，先把全部
`PUBKEY_PATHS` 下载到 root 创建的临时缓存并逐项确认非空。设备配置 apply/save 完成后，
`install_ssh_pubkeys` 只读取这份本地缓存，不再发起 HTTP 请求，再写入最终账号的
`authorized_keys`。这样即使专属配置删除了 ZTP transit IP 或路由，SSH key 安装仍可完成；key
也不会在 apply 前提前写入并被最终账号配置覆盖。Cumulus、IB/NVLink NVOS 和未知型号分支共用
相同的 prefetch/install 两阶段逻辑。
固定的 `mgmt-server.pub` URL 始终保留在模板和渲染结果中；macOS 准备阶段该文件可以仍是空
占位且不会发布，Linux 正式 load 注入非空管理 key 后才能通过服务启动门禁。404、空响应或
格式不可用的来源只记录警告，不会写入 `authorized_keys`。写入前以 OpenSSH key
`type + Base64 blob` 为唯一身份去重，comment 不参与身份；已有 options/comment 和第一条 key 原样
保留。`~/.ssh` 或 `authorized_keys` 为 symlink/非预期类型时 fail closed，最终文件经同目录临时
文件设置 owner/mode 后原子替换。

同一断路约束也适用于专属配置 apply 失败后的默认配置回退。Cumulus 会在首个 `nv config` 前
依次预取 release 版本默认、release 全局默认、legacy 版本默认和 legacy 全局默认四个候选，
分别保存且记录固定优先级；NVOS 会提前预取其全局默认配置。回退函数只按该优先级消费非空、
非 symlink 的本地缓存，绝不在 apply 后调用 HTTP。全部候选均缺失时，预取阶段先给出警告；若
之后确实需要回退，则明确失败，不会把空文件交给 NVUE。

bootstrap 在第一条结构化日志之前就在 `/var/lib/nvidia-ztp/logs/` 中用 `mktemp` 创建本轮
唯一的 root-owned 普通文件（目录 `0755`、文件 `0644`），并从第一行直接追加到该持久文件。
同目录 `latest-log` 是 root-owned `0644` 普通文件，只保存本轮日志的安全 basename，并通过
临时文件加 `mv` 原子发布；监控优先使用它，不再用设备 wall-clock mtime 判断新旧。pointer
缺失时才兼容旧设备的 mtime 选择，pointer 存在但类型、owner、mode、内容或目标不安全时会
fail closed，避免未来时间戳的旧失败日志永久遮住后续成功日志。
它不再复用 `/tmp/ztp/ztp-result.log`，也不再在结束时把临时文件复制到 home；因此专属配置
删除 transit 接口、脚本中途失败或临时目录被清理时，已经产生的阶段证据仍会保留。状态根目录
使用 `0711` 以允许非特权监控进程穿越到公开日志子目录，但其中 applied YAML/receipt 仍为
root-only `0600`。已有设备的 `~/ztp-result.log_*` 仅作为监控兼容回退。

配置、公钥和默认回退缓存不再使用固定 `/tmp/ztp`。每次 bootstrap 都由 root 在 `/run` 下
创建独立的 `nvidia-ztp.XXXXXX` 工作目录，校验为 root-owned `0700` 后使用，并用严格前缀检查的
EXIT trap 清理；低权限用户预建目录、symlink 或替换缓存无法影响 root 随后 apply 的 YAML 或
写入的 `authorized_keys`。需要留存的失败 YAML、receipt 与上述日志始终写到持久状态目录，
不会依赖 `/run` 生命周期。

每次 YAML 完成 `nv config apply` 和 `nv config save` 后，bootstrap 尝试把原始下载字节保存为
root-owned `/var/lib/nvidia-ztp/last-success.yaml`，并把对应
`/var/lib/nvidia-ztp/receipt.env` 作为最后一个文件原子发布；两个文件均为
`0600`。receipt schema 1 记录 apply 状态/模式、来源文件名、eth0 MAC、UTC 时间和原始
SHA-256。`status` 固定为 `success`；专属配置（包括 patch baseline）使用
`source_kind=dedicated`，直接使用默认配置为 `default`，专属 YAML apply 失败并成功回退默认配置
则为 `fallback_default`，同时以 root-owned `0600` `last-failed-dedicated.yaml` 保存失败字节并记录
其 SHA-256。`fallback` 作为 V1 兼容来源值保留。receipt 写入失败只产生 WARN，不会把
已经成功的设备配置改判失败；读取方会用 hash 对不完整的两文件切换 fail closed。

Cumulus 与 NVOS 都会安装固定零参数
`/usr/local/sbin/http-manual-ztp-applied-config` 以及独立 sudoers。该 helper 不接受路径或参数，
只读取上述固定 root-owned 文件，并在校验目录/文件 owner、mode、大小、字段和 SHA-256 后输出：

```text
ZTP_APPLIED_CONFIG_V1
schema=1
status=success
source_kind=...
apply_mode=...
raw_sha256=...
source_name=...
eth0_mac=...
applied_at=...
[failed_raw_sha256=...]
---
<原始 YAML 字节>
```

只有当前设备账号（Cumulus 为 `cumulus`，NVOS 为 `admin`）被精确授权执行这一条 helper；不授予
任意文件读取、shell 或通用 sudo 权限。

渲染产物属于管理服务器运行态，`sync-code.py` 默认保护，不会用本地默认副本覆盖；只有明确
使用 `--include-ztp-runtime` 才同步，随后必须在交换机开始 ZTP 前重新运行 load。

维护模板后至少执行：

```bash
bash -n ztp/templates/ztp-bootstrap.sh
python3 DAY0-Prepare/11-load.py <project> --dry-run --skip-infra
```

不要直接把模板文件名写进 DHCP；设备只应下载 load 根据 `ztp_service_ip`、global URL 前缀和
`cumulus_profile` 派生并渲染的两份 bootstrap。
