# 运行与恢复

Docker 首次部署优先用参数化 `init` 原子生成私有配置；AIR mini 示例为：

```bash
sudo ./infra/docker/deploy.sh init --project <project> --scope air --mini
sudo ./infra/docker/deploy.sh doctor
```

无 Internet 的目标服务器应在联网、同架构构建端先执行
`sudo ./infra/docker/deploy.sh image-export /root/http-ztp-generic-<arch>`，并在项目电脑另行生成
Docker upload release；需要 switch image、offline apps 或 firmware 时再生成 shared-artifact bundle。
这些目录分别执行 `sha256sum --check SHA256SUMS`。目标端先由 upload installer verify/apply
archive，再只执行一次 `docker load --input http-ztp-ubuntu-24.04.tar`，最后使用
`image-metadata.json` 中的完整 image ID 执行 `deploy-preloaded`。不得手工解压到 live root。
`build-export` 只是 `image-export` 的兼容别名；两者只生成 generic image 三件套，不改变服务容器
生命周期。四类制品的完整流程见
[《四类交付制品与 2026-12 部署流程》](../deployment/BUNDLE_WORKFLOWS.md)。

## 生命周期速查

Monitor 运维入口是 `/monitor/monitor.html`。首次访问使用 `nvis` 或 `cumulus` 登录；页面后续
刷新、采集、暂停和手工 ZTP 请求都在同一 `/monitor/` protection path 自动复用凭据，不再提示
第二次登录，但 Apache 会继续认证每个控制请求。Native 使用
`/usr/local/lib/http-ztp/control-auth.py rotate --user USER`，Docker 使用
`infra/docker/deploy.sh rotate-auth USER` 轮换；不得把密码放入 argv、env、日志或项目文件。
Basic HTTP 只允许位于隔离、ACL 保护的可信管理网。

| 目标 | Native/systemd | Docker/Supervisor |
|---|---|---|
| 预检 | `11-load.py --dry-run` | `deploy.sh doctor` |
| 首次在线激活 | `11-load.py --start-services ...` | `deploy.sh deploy`（已含 load/health）→ `status` |
| 首次离线激活 | 同左，由统一 load 消费本地依赖 | `deploy.sh deploy-preloaded <IMAGE_ID>`（已含 load/health）→ `status` |
| 没有 source write 且受管容器仍在运行（如 unload/失败恢复） | 重新运行统一 `11-load.py` | `deploy.sh load` → `health` / `status` |
| Service IP 从接口 A 移到接口 B | 重新运行统一 `11-load.py` 并按 systemd 合同收敛 | 网络稳定且没有 source write 后执行 `deploy.sh reload-network` → `health` / `status` |
| 健康与状态 | `run_vm_validation.py --full-systemd ...` | `deploy.sh health` / `status` |
| 日志 | systemd/Apache/DHCP 与项目日志 | `deploy.sh logs` 和持久日志目录 |
| 撤销本轮发布 | `13-unload.py` | `deploy.sh unload` |
| 删除控制容器 | 不适用 | `deploy.sh down`（持久数据保留） |

命令中的脚本路径和完整参数以对应模块 README/`--help` 为准。不要跨列执行服务控制命令。
Linux Native 管理服务器执行表中 `11-load.py` 时必须带
`--host-role=management-server`；Linux 工作站的配置准备必须带
`--host-role=workstation`，且不得启动服务。Docker 的受管 `hostctl` 子调用固定传递
管理服务器角色，不依赖操作员环境变量。Service IP 暂缺不会改变真实服务器角色：保持
服务安全停止，修复隔离测试网络后按原角色完整重跑。角色或公钥冲突不得靠覆盖旧公钥、
换 HOME、修改私钥或跳过测试解决。上述行为尚需独立 REAL_ENV 验证。

## Docker root 管理 SSH identity

Docker 管理面的日常账号固定为 `root`。宿主 authority 只能是
`/root/.ssh/id_ed25519`（及 `.pub`），容器持久副本只能是
`/var/lib/http-ztp-container/ssh/id_ed25519`（及 `.pub`）；容器只 bind 后者到 `/root/.ssh`。
四个写动作 `deploy`、`deploy-preloaded`、`deploy-project-preloaded`、`load` 都在同一个 lock 内、
第一项容器 lifecycle/image/project/activation/service mutation 之前 reconcile。`doctor` 只读 check；
Supervisor `11-load.py` 永不生成 key。

reconcile 只接受三类安全结果：两侧都不存在时在 host 生成再复制到 service；仅一侧有完整有效
Ed25519 pair 时复制到缺失侧；两侧 fingerprint 相同则零写入。半对、加密/RSA、owner/mode/link
错误、private/public mismatch 或两侧 fingerprint 冲突全部停止且不覆盖。本流程不执行 key rotation、
revoke 或 delete。

出现冲突时保存路径 metadata，仅通过公钥计算并比较 fingerprint，确认备份与来源后走批准的恢复
流程。不得手工复制或删除私钥，也不得改权限来“修好”检查。upload、sync、image 和诊断/evidence
均排除所有大小写形式的 `.ssh` 目录；支持包、日志和 receipt 不得包含 private key 内容。

这里的 trust boundary 只覆盖由 `hostlock` 串行化的官方 writer 与 root:root、`0700`、随机命名的
generation staging。helper 在 pre-publication、两次 leaf publication 之间及 pre-cleanup 都会重验
held stage 的 exact set/identity。Linux 没有 conditional unlink-by-inode API；non-cooperating
concurrent root 在边界之外，因为它 already has strictly stronger capabilities：可绕过 hostlock、
ptrace/改写 canonical authority、mount 或删除任意文件，所以最终 stat→unlink nanorace adds no
capability。private mount namespace is not used；不要把该边界解释为可抵抗恶意 concurrent root。

## Monitor cache authority N3 处置

已受损或有缺陷的 `www-data` 可反复放入同一碰撞 contaminant inode；
`same-identity breaker N=1→2→3` 会使 cache 发布 fail closed 并造成可用性拒绝。
`N=3 is not proof of an attacker`，也不是允许自动修复的信号。`automatic repair loops are forbidden`：
日常 provision/setup/load/health/guardian/CGI 只能 attest 且不清 breaker。取证只保存安全时间戳、
classification、stopped state 和 inode/type/mode/owner/hash metadata；绝不保存 payload、credential 或
Authorization bytes。确认 Apache 已停止后，Native 唯一入口是
`sudo ./infra/infra-setup.sh --recover-monitor-authority`；Docker 唯一入口是
`sudo ./infra/docker/deploy.sh recover-monitor-authority`，成功后仍保持容器停止，只能按其打印的
`sudo ./infra/docker/deploy.sh deploy` 后续指令恢复。操作员必须
`never manually unlink/chmod/rewrite` authority、breaker 或 recovery marker；若再次 wedging，保持
服务停止并调查 `www-data`/CGI，不得盲目重复 recovery。每次隔离验收只做一次 stopped-writer
recovery，并要求 `exactly one fixed warning`；随后重复同一个 N=1→2→3 注入，以证明
`re-wedging remains possible`，而不是把一次恢复误报成永久修复。

## 运行操作轴

### P2P 拆分模式与生成配置

P2P 推断出的 splitter profile 是硬件拆分模式的唯一来源：`1to2 → 2x/4 lanes`、
`1to4 → 4x/2 lanes`、`1to8 → 8x/1 lane`。只接一部分支路不能缩小父口模式。
direct VLAN、bond、BGP 和混合角色共用该规则；仅生成实际配置使用的父口，未使用的子口保持
最小声明，不增加虚假物理链路。超过 profile 范围的 lane 会阻止生成。

运行项目 P2P 生成器后，`output-p2p/<实际工作簿名>-splitter-profiles.json` 与 LLDPQ DOT
一起生成。它绑定 workbook、`01-inventory.log`、`02-port-mapping.log` 和 LLDPQ DOT 的 SHA256。
配置生成器只接受固定输入 `p2p.xlsx` 所指真实文件名的 sidecar，不会选择最新或其他同类文件。
输入变化、缺失 profile、无效 schema、重复条目或设备归属歧义都要求先重新生成 P2P，再生成配置；
不要手工填写 sidecar 或用 `03-splitter.log` 的静态示例代替它。

带有经过校验的 `source_yaml_*` receipt 的导入行仍逐字节透传，不会自动增加拆分声明。
改变硬件模式可能导致链路中断；规则验收不是设备侧测试结果，真机证据与风险见
`test_cases/REAL_ENVIRONMENT.md` 中的 `TC-REAL-SPLITTER-PROFILE-001`。

AIR JSON 单端链路可使用精确的 `unconnected`（未连接）或 `outbound`（外部出口）标记。
consumer 仍校验并收集另一端的真实端口；这些标记不生成虚假对端或配置。只接受两个真实
endpoint，或一个真实 endpoint 加一个合法标记；未知字符串、空白/大小写变体、两个标记及
缺失 node/interface 的 endpoint 会在创建输出目录前失败。不得手工删去合法单端链路来绕过
失败；应重新生成输入并核对 producer/consumer 版本。离线对比应显式绑定 AIR JSON 的 SHA256，
不能把目录中最新 mtime 当作来源证明；当前 AIR JSON 选择的 glob/mtime 回退尚属未关闭残留项。

### ZTP 后配置同步

设备已由受管 full-replace ZTP 成功配置、随后项目输入重新生成 latest 专属 YAML 时，可在 Monitor
的交换机状态页选择“配置同步”，或在管理服务器交互运行：

```bash
python3 ztp/manual-ztp.py <完整主机名> --replace-config --type prod
```

该入口先只读采集 `nv config show`、核对身份/release/上次完整 replace receipt，并显示规范化差异；
确认前不会修改设备。`interface.eth0.*`、`system.ssh-server.*`、所有
`system.aaa.user.*` 必须保持不变，其中不可观测的 `hashed-password` 使用上次已应用完整配置与新配置
比较。patch/AIR baseline receipt、缺失 AAA、运行态漂移或 preview 后任一指纹变化都会拒绝。

确认后执行整份 `nv config replace`、apply、save；这会删除任何未出现在新生成 YAML 中的现场手工
配置。control-plane ACL 按 owner 已接受风险不属于保护前缀，仍可能中断当前 SSH。首次真机验证只能
在有 console/OOB 和可回滚快照的实验设备进行，见 `TC-REAL-CONFIG-SYNC-001`。不得用 patch、伪造
prior full config、跳过 receipt，或在设备 ZTP/其他人工操作正在运行时强行同步。

### 同一 Service IP 换接口

这里的“换接口”只表示地址值、项目输入和源码均未变化，宿主网络工具已把同一个地址从接口 A
唯一移动到接口 B，且新接口、地址和全表 IPv4 route 在观察窗口内稳定。

- Native：重新执行完整 `11-load.py`，由统一事务重新收敛 Apache、DHCP、release 和 worker。
- Docker：`reload-network → health → status`，只重建动态 listener plan 和服务 authority。

不要只重启宿主 `isc-dhcp-server`，也不要直接执行容器 `supervisorctl restart dhcpd`。

### Service IP 地址值改变

Service IP 地址值改变属于 source write，因为权威值来自项目 DHCP subnet 输入。必须回到项目电脑
修改输入、执行正式 load 和全量测试，再走受控 upload/sync；Native 随后完整 load，Docker 随后
`deploy`，或使用通过当前 live manifest、runtime contract 与 image-coupled 记录核验的既有
`deploy-preloaded <IMAGE_ID>`。不得用 `reload-network` 掩盖输入漂移。

### 宿主或容器重启恢复

Native 保存并核对 systemd unit、DHCP/Apache listener、worker 和 parent release；Docker 先执行
`health → status`，自动 resume 未通过时保存 activation/quarantine、runtime plan、Supervisor 和
日志证据，再按原因选择无 source write 的 `load`、网络专用 `reload-network` 或 source write 后的
`deploy`。不得先删除容器或手工拉起单个进程。

### 部署事务中断恢复

从最后一个已验证 checkpoint 继续：已验证 upload 不重复覆盖，已验证 `docker load` 不重复导入，
已验证 immutable image ID 不回退到 tag。任何 archive/manifest/source/container 身份不一致均
fail closed；只上传未部署时使用 `--deploy-uploaded`，可信中转使用 server-side installer，禁止
手工解压 live root。

### 多 Service IP、VLAN 子接口与 DHCP relay

每个 listener 都必须由项目 subnet、当前 Linux 地址/前缀和 ifindex 唯一推导。Docker allowlist
只能收窄，不能扩大；可能漂移到接口 A/B 时应在首次配置中同时允许，或留空继续按权威输入动态
推导。relay-only 网段必须显式配置 ingress，管理口、NAT 口和 `docker0` 不得被自动加入。

### amd64 与 arm64 预构建镜像

预构建 generic image bundle 只能部署到相同 CPU 架构；每个架构都独立保存 image tar、
`image-metadata.json`、`SHA256SUMS` 和完整 immutable image ID。upload archive 与外部 installer
属于另一个独立目录，也必须完整保存。跨架构导入、仅凭 tag 或只复制任一目录中的部分文件都必须
拒绝。

### 最终物理交换机验收

本地 contract、Ubuntu VM 与 AIR simulation 通过不等于物理设备通过。最终还要保存真实 DHCP
DORA、bootstrap HTTP、eth0/前面板接口身份、YAML apply receipt、SSH、必要的系统升级和 Service IP
换接口后的再次 ZTP 证据；没有执行的层级不得写成 PASS。

## 更新后怎么做

- Docker tar/sync 成功写入会停止精确受管容器并提交 `stop + rebuild-required` 状态；下一步必须执行
  `deploy` 重新 build/recreate。若已有与当前 live 源码身份链匹配且经验证的预加载镜像，则重新执行
  `deploy-preloaded <IMAGE_ID>`。不得在 source write 后执行 `load`。
- 单独的 `load → health/status` 仅用于没有 source write 且受管容器仍在运行，例如
  `unload` 后重新激活或失败恢复。
- Service IP 从接口 A 移到接口 B 后使用 `reload-network → health/status`。Docker 的网络移动恢复
  只核对并重写动态 listener plan，不重新运行 load 或生成项目制品，然后在 Supervisor 下重启服务；
  不得运行宿主 `systemctl restart isc-dhcp-server`，不得直接执行 `supervisorctl restart dhcpd`。项目或源码有写入
  时仍必须 `deploy` 或使用新鲜、匹配当前 source authority 的 `deploy-preloaded`。
- 配置、代码或接口发生漂移：运行态必须保持 inactive/quarantine，修复权威输入后显式重试；
  不允许跳过 receipt、identity、health 或 content 校验。

## 先保留证据

故障时先保存当前命令退出码、完整 stderr、source/image/container identity、activation/quarantine、
Supervisor 和服务日志，再决定是否重试。只读支持包入口是
`tools/collect-ztp-diagnostics.py`。不要以重建或清理容器作为第一步，
尤其不要删除标签或 bind 不匹配的同名 foreign container。

交换机上的 `/var/lib/nvidia-ztp/logs/ztp-last-run.log` 是当前一次 ZTP 时间戳日志的固定名硬链接，
可直接 `tail -f` 查看正在追加的内容；下一次运行会原子切换到新的日志 inode，旧时间戳文件仍保留。
`latest-log` 仍是监控和诊断脚本使用的单行文件名指针，不得改成链接或手工重写。固定名目标若为
符号链接/目录等不安全类型，bootstrap 只告警并保持原样，不能为了便利入口阻断配置应用。

## 恢复原则

统一事务失败后，从第一个未通过的 checkpoint 恢复；已经证明且不可变的 upload、OCI tar、image
ID 不重复写入。服务异常由所选后端恢复：Native/systemd 查宿主 unit，Docker/Supervisor 查容器
PID 1、受管 program 和 guardian。网络地址缺失只报告给宿主管理员，本项目不修改 NIC/Netplan。
