# Real-environment acceptance cases

这里保存不能在本机隔离测试中安全、真实地完成的验收案例。它们不是自动化回归的替代品；
对应解析、事务和失败分支仍应在 `test_*.py` 中使用 fixture 自动覆盖。

## TC-REAL-DHCP-001 — AppArmor 与 DHCP 事务安装

- Ubuntu 管理服务器启用 AppArmor enforcement。
- 确认首次 `dhcpd -t` 使用 `/etc/dhcp/.load-dhcp-transaction-*/staged/`。
- staged 与 final 两次语法检查均通过；无 AppArmor DENIED。
- 四个最终文件 hash 与 DHCP manifest 一致，临时事务目录已清理。
- 任一步失败时 parent release 未提交，旧 DHCP 与 YAML latest 已恢复。

## TC-REAL-DHCP-002 — Cumulus/NVOS/未知平台 DORA

- 抓包验证 option 60 Cumulus 获得 option 239。
- 验证 option 61 `NVOS##` 与 option 77 `NVOS-ZTP` 获得 option 67。
- 真正未知平台只能获得 lease，不得收到 ZTP URL/bootfile。
- DHCP release、expiry、地址重分配后旧身份不得继续有效。

## TC-REAL-OOB-001 — OOB 双路径与 transit 身份

- OOB Leaf 用前面板 swp 从 ZTP server transit 网段取得 bootstrap。
- bootstrap 使用 eth0 MAC 下载唯一专属 YAML。
- apply 后 transit 路径消失，监控只用最终 eth0 地址 SSH，并再次核对管理 MAC。
- 同 IP 重分配、跨 AIR/Production 或伪造 HTTP GET 均不得冒认 canonical 身份。

## TC-REAL-ZTP-001 — Cumulus 完整 ZTP

- 验证版本、网络、专属/default 配置、`nv config apply/save`、SSH key、持久日志和 receipt。
- 日志从第一行写入 `/var/lib/nvidia-ztp/logs/`，latest pointer 指向本轮文件。
- `/run/nvidia-ztp.*` 私有工作区在退出后清理。
- apply/save/key 任一步失败时页面阶段、证据和回退状态准确。

## TC-REAL-NVOS-001 — NVOS 完整 ZTP

- 分别验证 IB/NVLink、eth0/eth1 身份、option 61/77、apply/save 和重启。
- 未绑定 NVOS 不得进入正式 IB/NVLink 完成状态或触发错误 SSH。
- factory reset、强制 ZTP 和 image/version 分支均形成新的轮次证据。

## TC-REAL-MONITOR-001 — 轮次、重启与跨时区

- 手工 ZTP/reset 前后改变 timezone，验证 network/version 不会永久等待。
- boot ID、boot time、latest-log pointer 与 log mtime 必须共同证明本轮。
- 重启窗口的瞬态 SSH failure 不得提前把操作终止为失败。
- 旧日志、未来 mtime、同 boot DHCP renew 均不得晋级新轮次。

## TC-REAL-MANUAL-001 — 当前运行配置比较

- 在设备运行态增加一个 latest 中不存在的配置。
- preview 必须以 selector-normalized `nv config show` 对比 current latest 并显示变化路径。
- receipt 只作为审计/TOCTOU 证据，不能掩盖运行态漂移。
- preview 后修改运行配置或发布 release，confirm 必须拒绝旧指纹。

## TC-REAL-TIME-001 — 时间检测与同步按钮

- 验证同步前页面显示 offset/uncertainty，按钮只影响时间状态，不重置 ZTP round/index。
- `abs(offset) + uncertainty > 5s` 必须为 warning/failed，不能报告成功。
- 高 RTT、设备时间向前/向后跳变和 NTP 后续校时均需覆盖。

## TC-REAL-HANDOFF-001 — 不同采集类型错峰完成

- 在同一项目中让 AIR Ethernet、Production Ethernet、IB 和 NVLink 分别在不同时间完成 ZTP。
- 某组全部正式设备达到 100% 后应立即生成该组采集归档，不等待其他类型。
- 同组仍有设备等待、身份待定或动态转正时，该组不得提前交接，但不得阻塞兄弟组。
- 让一个采集器失败，确认只有该组退避/重试，其他就绪组仍能成功并持久化签名。
- 重启 ZTP monitor 后已成功组不重复采集；后完成组仍能独立交接。
- TAN、OOB、OOBofOOB 和角色等 AIR/Production 展示子类不作为独立门禁，按所属采集组验收。

## TC-REAL-DEPLOY-001 — 上传、锁与常驻进程更新

- 中断 rsync 后从 `.partial` 续传并重新验证 SHA-256。
- sync、tar deploy 与 load 竞争时只能有一个持有 `.deployment.lock`。
- marker 清除前 load 必须拒绝；失败 marker 保留供人工诊断。
- 成功后重新 load，确认 worker、monitor 页面、Apache policy 和 bootstrap 都加载新版本。

## TC-REAL-CRASH-001 — 断电与磁盘故障

- 仅在隔离实验服务器执行磁盘满、SIGKILL 和断电注入。
- 覆盖 child latest、DHCP 四文件、parent release 和服务启动各提交边界。
- 重启后不得出现“新 parent + 旧/混合 DHCP”或对外暴露半代配置。
