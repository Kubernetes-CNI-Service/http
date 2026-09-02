# NDR bringup 工具

## 在整体架构中的位置

本目录是 InfiniBand 专项 bring-up/升级工具，不属于自动 ZTP 主链。输入和风险确认由操作者
负责，输出通过 setup 管理的项目结果链接归档，随后可随 download/import 回收。整体交付流程
见根目录 `USER_MANUAL.md`；本目录因历史安全限制只应在专项场景使用。

本目录保存旧版 NDR 信息采集和 OS/CPLD 升级脚本及其输入文件。两个入口不再内置密码：
采集默认只允许 SSH key，显式设置 `IB_SWITCH_PASSWORD` 时使用 `sshpass -e`；host key 默认
`accept-new`，只有明确传入 `--insecure-host-key` 才进入实验室兼容模式。

`ndr-upgrade-logs/` 是由 `DAY0-Prepare/01-a-setup.py` 管理的项目动态链接，目标为：

```text
DAY0-Prepare/<当前项目>/99-output-ib_nvl/bringup/ndr-upgrade-logs/
```

切换项目时该链接自动切换。可用 `--output`/`--error-output`/`--log` 把证据明确写入该项目目录；
脚本拒绝把输出写到符号链接。

## 脚本逻辑

- `data-collect-IB.sh` 读取 `IB-switches-IP.log`，检查 `sshpass`，逐台通过 MLNX-OS `cli`
  执行 images、inventory、module、power、temperature、fan、version、CPLD、IB interface 和
  running-config，追加到 `IB-SW-show.log`；缺少 sshpass 时写 `error-show.log`。
- `OS-CPLD-upgrade.sh` 只处理经过 IPv4/DNS 校验的去重目标。`--dry-run` 只校验/打印计划且不
  联机；真实执行必须显式 `--yes`、提供镜像/可执行 CPLD 工具并通过环境变量提供密码。只有
  上传、安装和 reload 都成功的设备才进入等待与 CPLD 阶段。

## 使用前检查

1. 在维护窗口确认设备确为脚本支持的旧 MLNX-OS，而不是 NVOS。
2. 修改 IP 清单、用户名和镜像；优先配置 SSH key。需要密码时只在当前进程环境导出
   `IB_SWITCH_PASSWORD`，结束后 shell 立即 `unset`。
3. 验证镜像 checksum、磁盘空间、当前/备用 image 和 CPLD 工具版本。
4. 先对单台设备运行采集；升级时持续通过 console/OOB 观察，不要仅依赖固定 sleep。

`updateswitchcpld` 的厂商接口强制要求 `-p`，因此真实 CPLD 阶段密码仍会短暂出现在该工具的
进程 argv；只能在受信任管理服务器和维护窗口使用。旧 MLNX-OS 的事务回滚/升级后健康验证仍
不如 XDR 工具完整，现代项目继续优先使用 XDR bring-up/upgrade 工具。
