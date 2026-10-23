# UFM（server_ufm）运行态监控采集：需求与流程

状态：需求已确认（2026-10-21）。第 2、5 节是 owner 的确认和答复，第 8 节的命令已在 ufm02 上实测。第 10 节是实现分工：本期实现的部分，以及交接给 codex dev 的部分。

代码位置以沙箱 `~/Desktop/ufm-setup`（基于 http-test 2644884）为准。开发分支上的行号可能不同，实施时请按符号重新定位。

## 1. 目标与边界

- UFM 用 `infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py` 完成配置和升级后，需要周期性地查看其运行状态，并采集信息。
- 新增两个脚本：`infiniband/monitor/ufm-info.sh`（状态与信息）和 `infiniband/monitor/ufm-ibdiagnet.sh`（IB 诊断）。
- 部署脚本不做采集：配置、诊断和周期任务各自保持授权与状态边界（《UFM 部署流程合并需求》中「日志回收和后续采集」一节）。
- 采集只读，不修改 UFM 配置；ibdiagnet 在 UFM 上写诊断输出文件，这一点除外。

## 2. 已确认的需求（owner 2026-10-21）

1. **执行方式与 `sw-info.sh`、`sw-link.sh` 完全相同**：
   - 由 `cron.sh` 把脚本传到 UFM 上执行；
   - 执行完成后取回结果，在部署服务器上存放。
   - 与交换机采集只有两点不同：执行对象是 UFM；结果存放在不同的目录。
2. **脚本位置**：`infiniband/monitor/ufm-info.sh`、`infiniband/monitor/ufm-ibdiagnet.sh`。它们是这个目录下的实体文件，不像 `sw-info.sh` 那样链接到 `ethernet/monitor`。
3. **调用方**：`infiniband/monitor/cron.sh`，即指向 `ethernet/monitor/cron.sh` 的链接，IB 模式。
4. **数据目录**：
   - `infiniband/monitor/ufm-info` → `../../DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-info`
   - `infiniband/monitor/ufm-ibdiagnet` → `../../DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-ibdiagnet`
   - 这两个链接和目标目录**由 setup 预先创建**，与现有的 `ib-info`、`ib-link` 相同。脚本和 `cron.sh` 不创建链接；链接缺失或断开时报错停止，不改写到别处。
5. **设备来源**：`infiniband/monitor/ib.csv`（指向 `../ib.csv`）中 `type=server_ufm` 的行。连接只用 `eth0_ip`，不用主机名。
6. **登录方式**：部署服务器公钥（`ufm-setup-upgrade` 已把 `publickey/*.pub` 装入 UFM root 的 `authorized_keys`），与 `cron.sh` 现有的 BatchMode 公钥登录一致。
7. 实现完成后交接给 codex dev。
8. **第一步：先让 `cron.sh` 支持 `server_ufm` 的信息采集**（owner 2026-10-21）。`server_mgmt` 以后再支持，这一期不涉及：它的行仍然像现在一样被 `cron.sh` 过滤掉。

## 3. 现有流水线（代码依据）

- **`cron.sh` 是唯一的采集器**（`ethernet/monitor/cron.sh`）。`infiniband/`、`nvlink/` 下的是链接，模式由清单文件名决定（:251-261、:875-902）。
  - 阶段顺序（:1833-2065）：密钥准备 → ETH info → SPX link → IB info → IB link → NV info → NV link → `post-collect.py`（ETH）或 HTML 生成（IB/NV）→ 保留期清理 → v2 emitter。
  - 每个阶段的调用形如 `collect_ib_info || collection_failed=1`（:1944-1945）：失败只记录，后续阶段照常执行。
- **单个阶段的模式**，以 `collect_ib_info` 为例（:1500-1550）：
  1. `scp` 脚本到 `${IB_REMOTE_DIR}`（`/home/admin/monitor`）；
  2. `ssh` 后先 `rm -f monitor/*.info`，再 `nohup bash monitor/sw-info.sh &`；
  3. `sleep ${IB_WAIT}`（120 秒）；
  4. `scp` 取回 `*.info`，写成 `<dir>/<设备名>.info`；
  5. 核对取回的文件数等于目标数；
  6. 打包为 `ib-info/<UTC>.tar.gz`（`archive_collection_dir` :703）。
  - 设备并行度 `MAX_PARALLEL=8`（:234）。SSH 选项见 :284：BatchMode、`ConnectTimeout=10`、`StrictHostKeyChecking=no`。
- **保留期**：原为 7 天（:233、:1729-1734），当天之前的按天合并成 `YYYYMMDD-daily.tar.gz`。owner 2026-10-22 改为 3 天，见 4.4。
- **目标筛选**：awk 过滤（:1002-1021）只保留 eth/eth_spx/spx/air、ib、nvl，`server_*` 行被静默丢弃。
- **调用来源**：
  - `12-ztp-monitor.py` 的完成交接按类型组调用 `cron.sh`（:4968-4986）；
  - `monitor/switch-collection-worker.py` 按固定槽位调用（`tools/project_contract.py:58-71` 的 `COLLECTION_CYCLE_SOURCE_SLOTS`）。
  - worker 传给 `cron.sh` 的目标计划形状是封闭的 `{eth, spx, ib, nv, dynamic_identities}`（`cron.sh:1852`、worker :3006）。
- **现有的 UFM 相关实现**：
  - D-70 采集合同 `tools/ufm_collection_contract.py:22-83`：
    - ibdiagnet 的固定参数和在 UFM 上的路径：`/var/tmp/ibdiagnet2`、`/opt/ufm/files`、`/root/monitor/ibdiagnet`；
    - 归档名 `ibdiagnet2_<run-id>.tar.gz`；
    - run-id 格式为 `YYYYMMDD-HHMM-(prod|air)-<16 位 hex>`。
  - `infiniband/prod` 槽位里有可选的 iblinkinfo 采集：需要 root 记录 `/var/lib/http-ztp-container/ib-producer-authority/<key>.json` 才会执行（worker :2856-2900）。
  - `monitor.html` 已有 UFM 标签页，只显示经过校验的回执（`generate-monitor-html.py:1966-2033`）。
  - **目前没有任何实现在监控 UFM 服务器本身的状态**（服务、版本、HA、IPMI、磁盘等）。

## 4. 流程

### 4.1 第一步：`cron.sh` 支持 `server_ufm` 采集

做法是在 `cron.sh` 中新增一个「服务器」类别，与交换机的 ETH/IB/NV 类别并列，执行模式完全相同：传脚本、远端后台执行、等待、按确切文件名取回、核对数量、打包、保留期清理。

**目标生成**：在 awk 过滤（`cron.sh:1002-1021`）的同一处，另外从 `type=server_ufm` 的行生成 UFM 目标文件，每行为 `名称|eth0_ip`。交换机类别的过滤保持不变，所以 `server_*` 行仍然不会进入交换机阶段；`server_mgmt` 这一期不采集。

**UFM 的执行参数**：

| type | 远端用户 | 远端目录 | 采集脚本 → 本地数据目录 |
|---|---|---|---|
| `server_ufm` | `root` | `/root/monitor` | `ufm-info.sh` → `ufm-info/`；`ufm-ibdiagnet.sh` → `ufm-ibdiagnet/` |

- 脚本放在 `cron.sh` 所在的监控目录（IB 模式下是 `infiniband/monitor/`），数据目录是该目录下由 setup 预先建好的链接。
- 没有 `server_ufm` 行时：记一行「无 UFM 目标，跳过」。
- 以后支持 `server_mgmt` 时，在这张表里加一行，并配上它的采集脚本。

**在流程中的位置**（IB 模式，直接调用路径；owner 2026-10-21：与交换机并行）：

```
UFM info 启动 → IB info（sw-info，等 120 秒）→ UFM info 取回
UFM ibdiagnet 启动 → IB link（sw-link，等 180 秒）→ UFM ibdiagnet 取回
→ 生成页面（本轮采到任何数据就执行）→ 保留期清理 → 结果输出
```

- UFM 的脚本先启动，再走交换机阶段；交换机阶段固定等待期间 UFM 已经跑完，回来直接取回，不增加总耗时。
- 没有 IB 交换机时（例如 `--type server_ufm`），UFM 自己轮询：info 最长 120 秒，ibdiagnet 最长 180 秒（与 `IBL_WAIT` 相同；owner 估计 ibdiagnet 在 120 秒以内）。
- **生成页面不再依赖整轮成功**（owner 2026-10-21）：采集项很多（eth/ib/nvl 的 info 和 link、UFM），不知道哪一项会失败，只要本轮采到了任意数据（`INFO_ARCHIVE`、`LINK_ARCHIVE` 或 UFM 数据）就调用 `generate-monitor-html.py`。ETH 仍走 `post-collect.py`（按本轮确切归档）。

**与交换机结果合同隔离**（实现约束，读代码后确定）：`cron.sh` 给 worker 和 12-ztp-monitor 的机器结果，由 `PLANNED_DEVICES`、`DEVICE_FAILURES`、`collection_failed` 三者决定（`cron.sh:737-817、1944-2065`）。`collection_failed` 一旦置位，就会输出一份「失败」结果（页面生成现在不受它影响，见 4.1）。因此：
- UFM 不写入 `PLANNED_DEVICES` 和 `DEVICE_FAILURES`，不复用会写入失败记录的 `run_parallel`，也不置 `collection_failed`。UFM 采集失败不能被当成交换机采集失败。
- UFM 失败不置 `collection_failed`，不影响交换机的机器结果，也不影响页面生成。
- UFM 失败的处理参照现有的「设备级失败」：记 ERROR 日志，最后一行改为 `cron finish with UFM warnings`，退出码保持交换机的语义不变。
- **worker 路径（页面触发的自动采集）也采 UFM**（owner 2026-10-21 选 A）。
  - worker 冻结的目标计划从 5 个键扩为 6 个键：`{eth, spx, ib, nv, dynamic_identities, ufm}`。`ufm` 只在 infiniband 槽位非空，内容是冻结清单中的 `server_ufm` 行（`名称|eth0_ip`，按清单顺序；没有 eth0_ip 的行跳过）。
  - worker（`_collection_target_plan_matches_sources`）按冻结清单逐行核对 `ufm`，多一行、少一行、改了 IP 都拒绝；其它槽位的 `ufm` 必须为空。
  - v2 证据生成（`collection_v2_emitter.py`）和 REQ7 的 IB 周期读取（`collection_ib_cycle_binding.py::rebuild_ib_target_plan`）用同样的 6 键形状。UFM 仍不计入 planned/succeeded。
  - 更正（2026-10-21）：此前 worker 路径不调用 `parse_csv_hosts`，UFM 目标文件始终为空，实际是静默不采；原先写的「会记一行说明」不成立。
  - 12-ztp-monitor 的完成交接走直接调用（`bash infiniband/cron.sh`，见 `12-ztp-monitor.py:4968-4986`），同样会采集 UFM。
- `server_ufm` 行没有 `eth0_ip` 时只跳过这台 UFM（stderr 提示），不再让整个 IB 车道的 CSV 解析失败。
- SSH 选项沿用 `cron.sh` 现有的（BatchMode、部署服务器公钥）。UFM 用 root 登录，不套用交换机的 cumulus/admin。公钥按第 11 节：先用公钥登录，失败时交互运行可输入密码，登录后部署公钥（`ufm-setup-upgrade` 通常已经装好公钥）。

### 4.2 `ufm-info.sh`（在 UFM 上执行，两台都采）

1. `cron.sh` 用 `scp` 把脚本传到每台 UFM 的 `/root/monitor/`，执行前先删除上一轮的 `*.info`，再用 `nohup bash monitor/ufm-info.sh &` 在后台执行。
2. 脚本只读采集，输出格式与 `sw-info.sh` 相同（命令清单见第 8 节）。先写临时文件，完成后原子 `mv` 为 `/root/monitor/<hostname>.info`；同一台机器上加锁，不允许两次采集同时运行。
3. 启动 1 分钟后每 5 秒检查一次，快照一出现就取回（最长 120 秒，第 11 节），写成 `ufm-info/<UTC>/<名称>.info`；取回的 UFM 打包成 `ufm-info/<UTC>.tar.gz`，单台失败不影响其它 UFM。
4. **身份核对**：`cron.sh` 不校验主机密钥，所以要用 `.info` 中管理口（eno8303）的 MAC 与 CSV 的 `eth0_mac` 比对。不一致时，这台的结果不收录，记 ERROR。
5. **HA 状态只经 VIP 在主机上采**（owner 2026-10-21）。
   - HA 由 `ufm-setup-upgrade` 在主机上启动。HA 还没配好时 VIP 无法访问；采集默认 HA 正常，登录 VIP 获取。备机上不执行 HA 命令。
   - 与每台的快照同时进行：`cron.sh` 把脚本传到 VIP 所在主机的 `/root/monitor/ha/`，执行 `ufm-info.sh --ha`。脚本放在单独的目录，不会覆盖这台机器上可能还在运行的 `monitor/ufm-info.sh`；`--ha` 模式也用单独的锁。
   - 采集内容：`hostname`、`ip -br link`、`ufm_ha_cluster status`、`ufm_enterprise_sanity.sh`，输出 `/root/monitor/<hostname>.ha`。
   - 取回后按 `.ha` 中的管理口 MAC 认出是哪台 UFM，存为 `ufm-info/<UTC>/<名称>.ha`，与 `.info` 一起打包；MAC 不属于 `ib.csv` 中的 UFM 时不收录。
   - VIP 无应答时记 `SKIPPED`「HA 未就绪」，不算失败。global 中没有 VIP 时同样跳过。
   - 每台的 `ufm-info.sh` 不再执行 `ufm_ha_cluster status`。

### 4.3 `ufm-ibdiagnet.sh`（登录 VIP 执行）

**owner 给出的手工命令（2026-10-21）**：

```
docker exec -it ufm /opt/ufm/opensm/bin/ibdiagnet --sc --extended_speeds all -P all=1 --pm_per_lane --get_cable_info --cable_info_disconnected --get_phy_info --routing --sharp --phy_cable_disconnected --rail_validation
docker exec -it ufm sh -c "tar -zcvf /opt/ufm/files/ibdiagnet2_$(date +%Y%m%d-%H).tgz /var/tmp/ibdiagnet2/*"
docker cp ufm:/opt/ufm/files/ibdiagnet2_*tar.gz /root/
```

可以看出：UFM 运行在名为 `ufm` 的容器里；ibdiagnet 在容器内执行，参数与 D-70 的固定参数相同；在容器内打包到 `/opt/ufm/files`，再用 `docker cp` 拷到主机。

**owner 2026-10-22 实测并补充的命令**（`ufm-manual.log` 第 2101–3161 行）：

```
docker exec ufm sh -c "/opt/ufm/opensm/bin/ibdiagnet --sc --extended_speeds all -P all=1 --pm_per_lane --get_cable_info --cable_info_disconnected --get_phy_info --routing --sharp --phy_cable_disconnected --rail_validation"
docker exec ufm sh -c "tar -zcvf /opt/ufm/files/ibdiagnet2_$(date +%Y%m%d-%H).tgz /var/tmp/ibdiagnet2/*"
mv /opt/ufm/files/ibdiagnet2_<时间>.tgz /root/monitor/ibdiagnet/
docker exec ufm /opt/ufm/opensm/sbin/iblinkinfo > /root/monitor/iblinkinfo/iblinkinfo_$(date +%Y%m%d-%H).log
```

- 这次 ibdiagnet 跑了约 6 分钟（06:44:48–06:50:50）。
- 主机的 `/opt/ufm/files` 就是 master 挂进容器的同名目录，所以不用 `docker cp`（owner 2026-10-22）。
- iblinkinfo 输出约 12 MB；stderr 上有 `Node Neighbor GUID ... doesn't exist` 之类的告警。

**适配后的流程**（owner 2026-10-22 定稿）：

| 步骤 | 位置 | 命令或动作 |
|---|---|---|
| 1 | 部署服务器 | `cron.sh` 从 `01-global.yaml` 读取 VIP，生成 run-id `YYYYMMDD-HHMM-prod-<16 位随机>`（含分钟级时间戳）。VIP 无人应答时记 SKIPPED，注明「HA 未就绪」。 |
| 2 | 部署服务器 | 按失败计数决定本轮采什么：默认 ibdiagnet；ibdiagnet 连续失败 3 次后改采 iblinkinfo，此后每 6 轮再试一次 ibdiagnet，成功即清零切回。计数在 `ufm-ibdiagnet/.ibdiagnet-state`（`failures`、`since_probe`）。SKIPPED 不改计数；登录 VIP 之后的任何错误都按失败计。 |
| 3 | UFM（VIP 所在） | `cron.sh` 把脚本传到 `/root/monitor/`，后台执行 `bash monitor/ufm-ibdiagnet.sh <run-id> [--iblinkinfo]`。同一个会话里读 `ip -br link`，按管理口 MAC 认出执行节点；之后的轮询和取回都走这台自己的地址（兼容 failover）。 |
| 4 | 容器内 | ibdiagnet：`docker exec ufm sh -c '<限时包装>' sh /opt/ufm/opensm/bin/ibdiagnet <固定参数>`，限时 `timeout -k 30 900`（15 分钟；容器里有 `/usr/bin/timeout`），输出记到 `/root/monitor/ibdiagnet/ibdiagnet2_<run-id>.log`。 |
| 5 | 容器内 → 主机 | 本轮写出 `ibdiagnet2.net_dump` 才算成功（看它的修改时间）。在容器里 `tar -zcf /opt/ufm/files/ibdiagnet2_<run-id>.tgz.part -C /var/tmp ibdiagnet2`，打包完改名；再在主机上 `mv /opt/ufm/files/ibdiagnet2_<run-id>.tgz /root/monitor/ibdiagnet/…tgz.part`（跨文件系统，先 `.part`），确认归档里有 `ibdiagnet2/ibdiagnet2.net_dump` 后改名。 |
| 4' | 容器内 | iblinkinfo（降级时）：同样限时，只取 stdout 写到 `/root/monitor/iblinkinfo/iblinkinfo_<run-id>.log`，stderr 另存 `.stderr`；超过 64 MiB、没有 `Switch` 行或超时都算失败。 |
| 6 | UFM 主机 | 执行节点身份（hostname、`ip -br link`）写到 `<前缀>_<run-id>.node`；最后写完成标记 `<前缀>_<run-id>.done`：`result`、`kind`、`run_id`、`artifact`、`sha256`、`size`、`rc`、`hostname`、`reason`。 |
| 7 | 部署服务器 | 启动后 5 分钟第一次探测，之后每 30 秒一次，最长 17 分钟（15 分钟加 2 分钟打包）。按确切文件名从执行节点取回，核对 sha256（ibdiagnet 还要有 net_dump），存为 `ufm-ibdiagnet/<run-id>_<节点短名>_ibdiagnet2.tgz` 或 `…_iblinkinfo.log`，UFM 的完成标记一并存为同名 `.done`。 |
| 8 | 部署服务器 | 执行节点的 MAC 必须是 `ib.csv` 中某台 `server_ufm` 的 `eth0_mac`，否则不收录（VIP 可能被别的设备占用）。启动时就核对，取回时再核对 `.node` 是同一台。 |

- **重叠**：页面发起的周期采集是上一轮结束后再按间隔排下一轮，不会重叠；`cron.sh` 自己的锁被占用时，本轮跳过，日志写「上一轮采集仍在运行……本轮跳过」。
- **锁**：同一台 UFM 上同一时间只允许一个 `ufm-ibdiagnet.sh` 在运行（两种模式共用一把锁）。收到 INT/TERM 立即退出，不写完成标记；锁目录没有 pid 且不到 60 秒视为对方正在加锁。
- **UFM 上的保留**：每种各保留最近 3 次。

### 4.4 保留期与展示

- **设备上的回收**（owner 2026-10-21 询问）：
  - **交换机 `~/monitor/`**：每次采集前 `rm -f monitor/*.info`、`*.link`（`cron.sh:1428` 等），只保留最近一份；脚本本身每次被重新传上去覆盖；`/tmp` 下的临时文件在脚本退出时由 trap 清理。
  - **UFM `/root/monitor/<hostname>.info`**：同样，每次执行前删除旧文件，只保留最近一份。
  - **ibdiagnet**：
    - 容器内 `/var/tmp/ibdiagnet2` 每次被覆盖，只有一份；
    - `/opt/ufm/files/ibdiagnet2_<run-id>.tgz`（主机和容器是同一个目录）在主机上 mv 走，不留副本（owner 2026-10-22：不用 `docker cp`）；
    - 主机 `/root/monitor/ibdiagnet/`、`/root/monitor/iblinkinfo/` 各保留最近 3 份，下次运行开始时删除更早的。
- **部署服务器**（owner 2026-10-22）：所有采集到的信息统一由 `cron.sh::cleanup_data_dirs` 保留 3 天：当天原样，前两天按天合并成 `YYYYMMDD-daily.tar.gz`，更早的删除。凡是以日期开头的文件都按这条规则处理，包括交换机归档、UFM 的 `.tgz`、`.log`、`.done`。CSV 不打包，方便页面直接读，只按 3 天删除。配置备份（`ztp/backup`）沿用它自己的版本数规则。
  - 删除超期文件原来用的是 `find "$dir"`，数据目录是指向 99-output-monitor 的链接，find 不会进入，所以超期文件从来没被删过（http `HEAD` 第 1800 行相同）。已改为 `find -H`。
  - `cronjob.log`：到 10 MB 就压缩成 `cronjob.log.1.gz`，最多保留 7 个；先复制再原地清空，crontab 的 `>>` 重定向继续写同一个文件。
  - **每类采集信息始终保留最新一份散放**（owner 2026-10-23）：只采 UFM 的一轮 cron 把前一天唯一的 IB 交换机归档打进了每日包，页面因此看不到任何 IB 交换机。现在每类文件里最新的一份照常打进当天的每日包，但散放的原件不删除，也不随过期删除，直到同类出现更新的一份。之后若散放文件与包内 index 记录的 sha256 和大小一致，就删除散放件；不一致的按迟到文件留在包旁边。「同类」指文件名去掉日期、分钟和 run-id 随机串（`YYYYMMDD-HHMM-(prod|air)-<16 位十六进制>`）后剩下的部分：`20261022-0659.tar.gz` 与 `20261023-0100.tar.gz` 同类；ufm01 与 ufm02 的报告、`.xlsx` 与 `.receipt.json` 各是一类。失败批次目录的处理不变。
  - `cleanup_data_dirs` 靠文件名开头的 `YYYYMMDD-HHMM` 识别日期，所以本地以 run-id 开头命名（owner 2026-10-22 定）：`<run-id>_<节点短名>_ibdiagnet2.tgz`、`<run-id>_<节点短名>_iblinkinfo.log`，UFM 的完成标记存为同名 `.done`。例如 `20261022-0644-prod-3f9c0a1b2c3d4e5f_ufm01_ibdiagnet2.tgz`。文件名中带执行节点，满足「按真实节点保存」的要求。UFM 上是 `ibdiagnet2_<run-id>.tgz`、`iblinkinfo_<run-id>.log`（owner 的前缀加 run-id）。
- 输出不得含有任何密码：UFM 和 BMC 的密码都不进脚本和输出，ipmitool 只用主机侧接口。注意 `99-output-monitor` 位于 Apache 目录树下。
- `monitor.html` 的 Switch Status 展示已接入（第 12 节）；issue tracker 的接入由 REQ7 负责（见第 5 节第 7 条）。

## 5. owner 答复（2026-10-21）

1. **`ufm-info.sh` 的采集内容**：先按 monitor 页面 Switch Status 表的列头来采（见第 8 节的对照表）。命令由 owner 先在 UFM 上手工执行验证，确认后再写进脚本。
2. **HA 状态**：`ufm_ha_cluster status`。owner 2026-10-21 补充：
   - 只经 VIP 登录主机采集，不在备机上执行；
   - HA 由 `ufm-setup-upgrade` 在主机上启动，HA 没配好时 VIP 无法访问；
   - 主机上同时执行 `ufm_enterprise_sanity.sh`（见 4.2 第 5 条）。
3. **ibdiagnet 在哪台跑**：登录 VIP 所在的设备执行。VIP 会在两台之间漂移，所以归档里必须记下实际执行节点的身份（hostname 和管理口 MAC），不能用 VIP 代替节点身份（需求文档「日志回收和后续采集」）。
   - HA 还没配好、VIP 无人应答时：记为 **SKIPPED**，注明「HA 未就绪」，不按 D-70 的「零目标失败」记为失败（owner 2026-10-21）。
4. **频率**：`cron.sh` 已经支持手工调用和自动调用，自动调用由 monitor 目录下的 html 页面发起。这一期不另设 ibdiagnet 的最小间隔，跟随 `cron.sh` 的调用。
5. **run-id**：说明见第 9 节。
6. **iblinkinfo**：~~只在 ibdiagnet 采集失败后尝试，默认关闭~~。owner 2026-10-22 改为：默认只采 ibdiagnet，连续失败 3 次后改采 iblinkinfo，每 6 轮再试一次 ibdiagnet（见 4.3）。
7. **数据的分析和展示**：由 monitor 脚本负责。owner 2026-10-21 补充：`ufm-ibdiagnet.sh` 完成后，接着完善 `generate-monitor-html.py`，把 UFM 数据解析后显示到 Switch Status 页面。同步到 issue tracker 由 REQ7 实现，这一期不考虑。owner 2026-10-21 再补充：卡片只显示设备信息；ibdiagnet 属于 link 信息，由 `generate-monitor-html.py` 分析后更新到 IB Link Validation 页面。
8. **`server_mgmt`**：以后会在 devices_config 和 global 中提供信息，目前没有具体需求，这一期不考虑。

## 6. 交接清单（codex dev）

> 2026-10-22 起由 Claude 在 http 树中实现（codex dev 交接后接手）：第 1、2、4 条已完成，见 14.3 末尾的「http 实现」。

1. **setup/unsetup**：
   - 创建和删除 `infiniband/monitor/ufm-info`、`ufm-ibdiagnet` 两个链接及目标目录；
   - `tools/_package_common.py` 的 `STATIC_SETUP_MANAGED_LINKS` 加上这两项；
   - 公开审计 `test_cases/audit_public_tree.py` 的链接白名单加上这两项。
2. **新 type**：setup/load 接受 `server_ufm`、`server_mgmt`；`12-ztp-monitor.py::read_devices` 跳过这两种类型，否则会被当成交换机去 SSH。详见 `infiniband/bringup/ufm-setup-upgrade/README.md` 的清单。这一项与监控是否采集 `server_mgmt` 无关，两种类型都要兼容。
3. **`cron.sh`**：
   - 按 4.1 生成 `server_ufm` 目标；
   - 增加 UFM 的两个阶段，以及 UFM 的用户、远端目录和等待时间配置；
   - worker 路径下的目标计划形状加上 `ufm`：已在沙箱中实现（owner 2026-10-21 选 A，见 4.1 和第 10 节），请 codex dev 评审。
4. **manifest**：两个脚本都要登记 `scripts` 和 direct `test_rules`，并加入一个与 `cron.sh` 组成的 workflow；套件可以用 `monitoring-collection`。
5. **`test_cases/REAL_ENVIRONMENT.md`**：真实 UFM 上的执行、ibdiagnet 的耗时和输出、取回与保留期。

## 7. 实现与测试计划

1. 先写测试：
   - **direct 测试**：在本地用模拟的 `ibstat`、`systemctl`、`ipmitool`、`df`、`ibdiagnet` 运行两个脚本，核对输出的分段、不含密码，以及 `.part` 原子改名。
   - **workflow 测试**：用模拟的 `ssh`/`scp` 跑 `cron.sh` 的服务器阶段，核对以下内容：
     - `server_ufm` 目标的生成，`server_*` 行不进入交换机阶段，`server_mgmt` 不被采集；
     - 传输、取回、计数、打包；
     - ibdiagnet 零目标时记为失败。
2. 实现顺序：先改 `cron.sh`，加上 UFM 目标和两个阶段；再写 `ufm-info.sh`；最后写 `ufm-ibdiagnet.sh`。
3. 在 实验环境的管理服务器 上实测，并登记到 `REAL_ENVIRONMENT.md`。

## 8. `ufm-info.sh` 采集内容：Switch Status 列头对照（ufm02 实测 2026-10-21）

输出格式与 `sw-info.sh` 相同：
- 文件头：设备名、类型 `UFM`、采集时间；
- 每条命令一段：`# Execute Command: <命令>` 加原样输出，命令在 `LC_ALL=C` 下执行；
- 结束标记，然后原子 `mv` 到 `/root/monitor/<hostname>.info`。

所有命令都只读，在 ufm02 上以 root 执行，均在 60 秒内返回。下表的「实测」列是 ufm02 上读到的值，或者能读到哪些内容。

| Switch Status 列 | UFM 上的命令 | 实测 |
|---|---|---|
| 主机名 | `hostname` | FQDN |
| SN | `dmidecode -s system-serial-number` | Dell 服务标签（7 位） |
| 型号 | `dmidecode -s system-manufacturer`、`dmidecode -s system-product-name` | `NVIDIA` / `UFM3.5` |
| SW 版本 | `cat /etc/ufm-release`、`grep PRETTY_NAME /etc/os-release` | `UFM_APPLIANCE=2.6.1-5`、`UFM_ENTERPRISE=6.26.1-5` 等 14 个组件；Ubuntu 24.04.4 LTS |
| BIOS 版本 | `dmidecode -s bios-version` | `2.8.2` |
| SSD 版本 | `lsblk -d -o NAME,MODEL,SERIAL,REV,SIZE,TYPE` | 2 块 Dell Ent NVMe CM7 3.2TB，REV（固件）`3.0.1` |
| ASIC 版本 | `ibstat` | CA type `MT4131`，Firmware `40.50.1002` |
| ASIC 温度 | 每个 `mlx5_*` 设备一条 `mget_temp -d <设备>`；设备从 `/sys/class/infiniband/` 动态列出，不含 `smi*`。`mst status -v` 里没有 `/dev/mst/` 设备时，先执行一次 `mst start`（记录在快照里）再读温度（owner 2026-10-23：备机上 MST 未加载，`mget_temp` 报 `mopen: No such file or directory`） | `mlx5_0` 为 64、`mlx5_1` 为 70（°C） |
| PSU 温度 | — | Dell 的传感器里没有 PSU 温度，这一列对 UFM 显示 `-` |
| （温度补充） | `ipmitool sdr type Temperature` | 两颗 CPU 的 `Temp`、`Inlet Temp`、`Exhaust Temp`；`Temp 1~3` 为 Disabled |
| PSU | `ipmitool sdr type 'Power Supply'` | `PS Redundancy: Fully Redundant`，两个 `Status: Presence detected` |
| FAN | `ipmitool sdr type Fan` | 16 个风扇的转速，以及 `Fan Redundancy: Fully Redundant` |
| CPU Use | `top -bn2 -d 1` | 与交换机相同，解析方法通用 |
| Disk Use | `df -PT` | `/`、`/opt/ha_data`（HA 数据盘）、`/boot/efi` |
| Mem Use | `free -b` | 与交换机相同 |
| NTP Sync | `timedatectl` | `System clock synchronized: no`（未同步，与部署时的提示一致） |
| 接口 | `ip -br link`、`ip -br addr`、`ibstat` | 以太网口状态和 MAC（含 `idrac` 主机直通口）；IB 口状态和速率 |
| BGP | — | UFM 不适用，显示 `-` |
| EVPN/MLAG Bond → HA | `ufm_ha_cluster status`、`ufm_enterprise_sanity.sh`（只经 VIP 在主机上执行，`ufm-info.sh --ha`） | 未配置时第一行是 `Error: HA is not configured ...`；配好后（owner 给的示例）有 Online、Masters/Slaves、资源组各资源的状态与所在节点、守护进程、DRBD 两端状态、VIRTUAL_IP；sanity 最后一行为 `Sanity tests completed successfully!` |
| 健康 | `systemctl is-active ufm-enterprise`、`systemctl list-units 'ufm*' --no-pager` | `ufm-enterprise: failed`；`ufm-chassis-health: running` |
| Uptime | `uptime -p` | 与交换机相同 |
| 采集 | 文件头中的采集时间 | 由 `cron.sh` 取回时记录 |

**解析时要注意（交给后续的 monitor 分析）：**
- `ibstat` 里除了 `mlx5_0`、`mlx5_1`，还有 `smi0`、`smi1` 两个 CA。它们的 GUID 分别和 `mlx5_0`、`mlx5_1` 相同（推断是多平面用的管理接口），统计 HCA 和端口时不能重复计数。
- 身份核对用 `ip -br link` 中 `eno8303` 的 MAC。

## 9. run-id 说明

run-id 是部署服务器为**每一次** ibdiagnet 采集生成的唯一编号，来自 D-70 合同（`tools/ufm_collection_contract.py:20、47-57`）。

- **格式**：`YYYYMMDD-HHMM-<环境>-<16 位十六进制随机数>`，例如 `20261021-0322-prod-3f9c0a1b2c3d4e5f`。
  - 时间是部署服务器发起采集时的 UTC 时间，精确到分钟；
  - 环境是 `prod`（生产）或 `air`（AIR 仿真环境）；
  - 随机数保证同一分钟内的两次采集不会重名。
- **用途**：
  - 由部署服务器生成后原样传给 UFM，UFM 上的文件名是 `ibdiagnet2_<run-id>.tgz` 或 `iblinkinfo_<run-id>.log`（owner 2026-10-22：时间戳精确到分钟加 run-id，run-id 本身以分钟级时间开头）；
  - 取回时按这个确切文件名取，不用通配符，所以不会取到上一轮留下的旧文件或别人的文件；
  - 本地存放也用同一个名字，一个文件对应一次采集，重跑不会覆盖上一轮的结果。
- **环境（prod/air）的来源**：建议直接用 `cron.sh` 自己判定的环境（`detect_eth_environment`）。

## 10. 实现分工

**进度（2026-10-21）**：
- ✅ `ufm-info.sh` 以及 `cron.sh` 中的 UFM info 阶段已实现。
  - 测试：`test_cases/test_ufm_monitor_scripts.py`（direct）、`test_cases/test_ufm_monitor_cron_workflow.py`（真实 `cron.sh` + 真实 `ufm-info.sh` 的 workflow），已在 macOS 和 Ubuntu 24.04 上通过。
  - 已有的 `cron.sh` 覆盖测试（599 个）通过。
  - manifest 已登记。
- `cron.sh` 的相关改动：
  - IB 车道的「空车道」检查把 UFM 也计入选中设备，只有 UFM 的项目或 `--type server_ufm` 不会被误判为空车道；
  - `parse_csv_hosts` 中的 UFM 目标文件默认为 `/dev/null`，单独切出来测试的解析函数不依赖它；
  - `test_monitor_stack_review` 中 UTC 时间戳的计数从 6 改为 7，因为新增的 UFM 阶段同样用 UTC 命名。
- ✅ `ufm-ibdiagnet.sh` 和 `cron.sh` 中的 ibdiagnet 阶段已实现，并改为与交换机并行（4.1）；页面生成改为「本轮采到任何数据就执行」。
  - 测试：direct 测试 14 个，workflow 测试 6 个，在 macOS 和 Ubuntu 24.04 上都通过。
  - 已有的 `cron.sh` 覆盖测试通过。其中 `test_project_contracts` 锁定的页面生成条件改为新条件（owner 2026-10-21 的需求变化）。
- ✅ 第 11 节的采集流程统一已实现。
  - 测试：`test_collector_retrieval`、`test_collector_publication`。
  - 取回端的临时文件放在目标目录下的隐藏子目录，文件名与正式文件相同，取回后再改名。
  - `test_collection_cycle_handoff_workflow` 的假采集器原来只写 `fixture-info`，现在补上与真实 `sw-info.sh` 一致的 `# Collect complete` 结尾；断言未改。
  - 覆盖 `cron.sh` 的测试和两组 handoff workflow（32 个）通过。
- ✅ `generate-monitor-html.py` 解析 `ufm-info` 归档，在 Switch Status 的 InfiniBand 组最上面显示 UFM Servers（第 12 节）。
  - 测试：`test_cases/test_monitor_ufm_status.py`（9 个），manifest 规则 `monitor_ufm_status_ui`。

**本期实现（沙箱 `~/Desktop/ufm-setup`）：**
1. `infiniband/monitor/ufm-info.sh`：在 UFM 上执行，按第 8 节的命令采集，输出格式与 `sw-info.sh` 相同。
2. `infiniband/monitor/ufm-ibdiagnet.sh`：在 UFM 上执行，接收 run-id；默认跑 ibdiagnet，加 `--iblinkinfo` 只跑 iblinkinfo（由 `cron.sh` 的失败计数决定，见 4.3）。
3. `cron.sh` 的直接调用路径（手工运行）：
   - 从 `ib.csv` 生成 `server_ufm` 目标；
   - VIP 从项目 global 的 `servers.ufm.vip` 读取；
   - 新增 UFM info 和 UFM ibdiagnet 两个阶段，以及取回、计数、打包和保留期。
4. 测试和 manifest 登记：每个脚本有 direct 测试；`cron.sh` 加两个脚本组成 workflow 测试。

**已在沙箱中实现，请 codex dev 评审（owner 2026-10-21 选 A）：**
1. **html 页面触发的自动路径采 UFM**（详见 4.1）。改动跨了 codex 的 collection-cycle 和 REQ7 代码：
   - `cron.sh`：输出和读入冻结计划时都带 `ufm` 键，删除 worker 路径跳过 UFM 的分支；
   - `monitor/switch-collection-worker.py`：两处形状检查改为 6 键，`_collection_target_plan_matches_sources` 按冻结清单核对 `ufm`；
   - `monitor/collection_v2_emitter.py`：形状改为 6 键，`ufm` 只允许出现在 infiniband 槽位；
   - `monitor/collection_ib_cycle_binding.py`：新增 `rebuild_ib_target_plan`，按冻结清单重建含 `ufm` 的计划；
   - `monitor/issue_tracker_switch_runtime.py`：两处计划构造补 `"ufm": []`；
   - 测试：新增 `test_ufm_worker_collection.py`（真实 worker 加真实 `cron.sh` 的 workflow，以及计划来源的 direct 测试）。另有 4 个已有测试文件中手写计划的 fixture 补了 `"ufm": []`（共 5 处），断言未改：`test_issue_tracker_switch_runtime.py`、`test_issue_tracker_switch_runtime_workflow.py`、`test_collection_ib_producer_workflow.py`（2 处）、`test_collection_ib_cycle_binding_workflow.py`。

**交接给 codex dev：**
1. （已由上面的实现取代）
2. **setup 预建链接**：
   - `infiniband/monitor/ufm-info`、`ufm-ibdiagnet` 两个数据目录；
   - `infiniband/monitor/01-global.yaml` → `../01-global.yaml`，供 `cron.sh` 读取 VIP，与现有的 `ib.csv` 链接同一模式；
   - 打包清单和公开审计白名单同步加上这些链接。
3. **新 type 兼容**：setup/load 接受 `server_ufm`、`server_mgmt`；`12-ztp-monitor.py` 跳过这两种类型。
4. **真实环境登记**：`REAL_ENVIRONMENT.md` 中登记 实验环境的管理服务器 上的实测结果。

## 11. 采集流程统一（owner 2026-10-21，适用于全部 eth/ib/nvl/UFM 的 info 和 link）

| 项目 | 统一后的规则 | 实现 |
|---|---|---|
| 等待方式 | 触发后先等 1 分钟，然后每 5 秒检查一次，文件一出现就取回；各阶段原有的上限不变：ETH/IB/NV info 120 秒，IB/NV link 180 秒，SPX 300 秒，UFM info 120 秒，ibdiagnet 180 秒 | `retrieve_when_ready`（`RETRIEVE_FIRST_WAIT=60`、`RETRIEVE_POLL=5`）；UFM 的取回用同样的时序 |
| 文件出现即表示采集完成 | 设备上的采集脚本把临时文件写在输出目录下的隐藏目录里，写完后同一文件系统内改名，取回时不可能拿到半个文件；`.info` 取回后还要核对 `# Collect complete`；部署服务器取回时也先写到目标目录下的隐藏子目录，核对后再改名 | `sw-info.sh`、`sw-link.sh`、`ufm-info.sh`、`retrieve_when_ready`；ibdiagnet 的完成标记 `.done` 在归档完成后才写 |
| 部分失败 | 某些设备采集失败，不影响其他设备 | 交换机原本就是这样：失败的设备从目标文件里剔除并记录，其余设备照常打包。之前第 11 节写的「数量不等就整阶段不打包」不准确，只在重名这类异常情况下才会发生。UFM 也按同样方式处理 |
| 身份核对 | 用管理口 MAC 确认连到的是对的设备 | 公钥准备阶段核对：交换机的 `eth0` MAC 必须等于 CSV 的 `eth0_mac`；UFM 的管理口 MAC 必须出现在设备上；CSV 没有 MAC 时退回原来的主机名核对；不符就跳过该设备。MAC 对照表在直接调用路径和 worker 冻结计划路径下都会加载 |
| 先公钥、失败再要密码、然后部署公钥 | 按登录失败的设备类型提示 | 交换机原本就是这样（`deploy_ssh_keys`）；UFM 也接入同一流程。提示语改为「Ethernet 交换机 / InfiniBand 交换机 / NVLink 交换机 / UFM 服务器 <用户> 密码 (attempt N/3): 」（保留原有的 `attempt N/3` 格式，已有测试按这个格式驱动终端输入）。UFM 的失败只写日志，不进入交换机的机器结果 |
| 清理日志的计数 | `found 0 tar.gz` 修正 | `cleanup_data_dirs` 的计数改用 `find -H`，会跟随数据目录链接 |
| 数据目录链接缺失 | 两个 UFM 数据目录都没有时，不连接任何 UFM；只缺一个时，只停对应的阶段 | 主流程在公钥准备之前检查 |

**其它保持的差异**：交换机按 `MAX_PARALLEL=8` 并行；UFM 只有两台，逐台执行。worker 路径（HTML 页面触发的自动采集）现在也采 UFM（4.1）。

## 12. Switch Status 展示：UFM Servers（owner 2026-10-21）

- **位置**：InfiniBand Switches 组的最上面，子类名为「UFM Servers」，卡片视图和列表视图都有。项目中没有 UFM 时不显示这个子类。
- **数据来源**：`infiniband/ufm-info/` 下最新的小时归档（`generate-monitor-html.py::load_ufm_status`）。
  - CSV 中的 `server_ufm` 如果不在归档里，显示为 MISSING 行，但仍放在 UFM Servers 内，不归入「未采集 · 可能掉线」。
  - IB 归档缺失或解析失败都不影响 UFM 的显示。
  - AIR 页面不显示（与 IB 一致）。
- **UFM 标签页**：暂不处理（owner 2026-10-21 第 7 条）。

**列的取值**（`parse_ufm_info_file`，列表仍是 21 列）：

| 列 | 取值 |
|---|---|
| 型号 | 厂商 + 产品名，例如 `NVIDIA UFM3.5` |
| SW 版本 | `UFM_APPLIANCE`，没有时用 `UFM_ENTERPRISE` |
| SSD 版本 | 每块 disk 的 lsblk `REV`，相同的合并为「`3.0.1 ×2`」 |
| ASIC 版本 | 真实 HCA（不含 `smi*`）的 CA type + 固件，例如「`MT4131 40.50.1002 ×2`」 |
| ASIC 温度 | 每个 `mlx5_*` 的 `mget_temp` |
| PSU 温度 | BMC 中名称含 PS/PSU 的温度传感器；Dell 没有，显示 `—` |
| PSU / FAN | `ipmitool sdr`：entity `10.N` 为电源；FAN 只计有转速读数的行；状态不是 `ok` 的计为故障 |
| Disk Use | `df -PT`，去掉 `/var/lib/docker/…` 和 `/run/…` |
| 接口 | 带 IPv4 的以太网口（不含 lo、docker、idrac 等）加真实 HCA 的 IB 端口。IB 口只有 `State: Active` 才算 up。规则如下：<br>• 物理状态为 Disabled 的口计入总数，但不标红（与交换机一致）。<br>• 链路已通但不是 Active 的口，标为「`<口> (Initializing / LinkUp，SM 未分配 LID)`」。这里的「SM 未分配 LID」只在 `SM lid: 0` 时出现。ufm01 在 2026-10-22 实测就是这种状态：UFM 本身就是 SM，`ufm-enterprise` 没有运行（例如还没配 HA）时，端口只能停在 Initializing。<br>• 其它情况按物理状态标注，例如 Polling。<br>`smi*` 与 `mlx5_*` 的 Node GUID 相同（实测），是同一块网卡的管理视图，不计入 |
| BGP | N/A |
| Bond 列 | 「HA: 主 · 在线 2/2」「HA: 备 · 在线 2/2」「HA: 离线 · 在线 1/2」；没有 HA 状态时为「HA: 未就绪」。鼠标悬停显示集群明细（DC、Online、Masters/Slaves、各资源、守护进程、DRBD、VIRTUAL_IP、sanity、问题）。卡片上为单独的 HA 行 |
| 健康 | 见下面的规则 |
| 卡片 Temperature | HCA 温度加 BMC 的温度传感器 |

**`ufm_ha_cluster status` 的两种格式**（`parse_ufm_ha_status`）：
- 旧示例的格式：行首写 `DRBD_CONNECTIVITY: Connected`，没有缩进，值不带方括号。
- ufm01 在 2026-10-22 实测（Pacemaker 2.1.6）的格式：`* Online:`、`Promoted:/Unpromoted:`；DRBD 段缩进两格，值带方括号（`  DRBD_CONNECTIVITY: [Connected]`），`VIRTUAL_IP: [x.x.x.x]` 也带方括号。
- 两种都能读。
- **修正记录**：最初版本只认旧格式，在新格式下 DRBD 一行都读不到，就默认为「正常」，DRBD 断开也不会报警。2026-10-22 已修正，并补了测试 `test_the_pacemaker_2_layout_from_ufm01_is_read_in_full` 和 `test_a_broken_replica_in_the_pacemaker_2_layout_is_not_missed`。修正前，后一条在断开的 DRBD 上得到 ok/ok。

**健康度**（`apply_ufm_ha_status`）：
- 两台的 HA 状态都来自主机经 VIP 采到的 `.ha`。节点名按短名、忽略大小写，与每台 `.info` 中的 `hostname` 对应。
- **owner 2026-10-22**：`ufm_ha_cluster status` 的结果是判断 HA 的依据。`ufm_enterprise_sanity.sh` 失败或没有输出时，只在主机的明细里加一行「提示：…」，不影响健康度。
- **主机**（在 Masters/Promoted 中）：
  - 资源都是 Started、`ufm-enterprise` 运行在本机、没有集群问题，为 OK；
  - 有资源没有运行、或 `ufm-enterprise` 运行在别的节点，为 ERROR；
  - 只有集群问题时为 WARNING。
- **备机**（在 Slaves/Unpromoted 中）：没有集群问题时为 OK，有则为 WARNING。备机上 `ufm-enterprise` 是 inactive 属于正常，不报警。
- **其它节点**：在 OFFLINE 中为 ERROR；在线但既不是主也不是备为 WARNING；不在集群中为 WARNING。
- **集群问题**（两台都会显示）：没有 quorum、在线节点少于配置数、守护进程不是 active、DRBD 不是 Connected、任一端磁盘不是 UpToDate。
- **没有 HA 状态**（VIP 无应答，HA 未就绪）：按每台自己的 `ufm-enterprise` 服务判定，active 为 OK，failed 为 ERROR，其它为 WARNING。
- 电源或风扇故障：OK 降为 WARNING。

**owner 确认（2026-10-21）**：
1. **HCA 温度阈值**：沿用页面通用阈值，70°C 黄，85°C 红（`mget_temp` 不提供阈值）。
2. **卡片只显示设备信息**：link 信息（ibdiagnet）不上卡片。由 `generate-monitor-html.py` 分析 ibdiagnet 数据，更新到 IB Link Validation 页面。
3. **`ufm_enterprise_sanity.sh`**：几秒就结束，沿用每条命令 60 秒的限时。

## 13. IB 链路校验闭环（owner 2026-10-21：参考 Ethernet 来做 IB）

**照 Ethernet 的流程**：
- Ethernet：采集后 `ethernet/monitor/post-collect.py` 用本次的确切归档跑 `tools/lldp-analyze-tool`，把 `<归档>-ethernet-topology-validation.xlsx` 写到 `99-output-p2p`，页面的 Eth Link Validation 读取它。
- IB 对应如下：

| | Ethernet | InfiniBand |
|---|---|---|
| link 原始数据 | 交换机 `eth-info` 归档中的 LLDP | UFM 上 ibdiagnet 的归档；连续失败 3 次后为 iblinkinfo 的 stdout 日志 |
| 期望拓扑 | P2P 生成的 `<p2p>-lldpq.dot`（load 调 `cumulus/template/P2P/b-xlsx_to_dot.py`） | P2P 生成的 `<p2p>-cvt.xlsx` 及 provenance（`nvos/template/P2P/p2p-to-validation.py`，load 接入待定，见下） |
| 分析器 | `tools/lldp-analyze-tool/analyze_lldp.py` | `tools/ibdiagnet-analyze-tool/analyze.py` |
| 调用方 | `ethernet/monitor/post-collect.py --archive <本次归档>` | `infiniband/monitor/post-collect.py --archive <本次归档>` |
| 输出 | `99-output-p2p/<归档>-ethernet-topology-validation.xlsx` | `99-output-p2p/<run-id>_<节点>-ibdiagnet-topology-validation.xlsx`（iblinkinfo 为 `-iblinkinfo-…`），旁边是分析器的 `.provenance.json` 和本采集器的 `.receipt.json` |
| 展示 | Eth Link Validation | IB Link Validation（同一套渲染代码；run-id 带 `-prod-`，归为 Production） |
| 分析失败 | 整轮失败，页面不刷新 | 只记 UFM 告警，页面照样刷新 |

**`cron.sh`**：
- `ufm_ibdiag_fetch` 取回并校验归档后，记下本次的确切路径（`UFM_IBDIAG_ARCHIVE`）。
- 刷新页面之前运行 `infiniband/monitor/post-collect.py`，失败时记 `[IB-CLOSED-LOOP] ERROR`，计入 UFM 告警。
- 分析在当次进行。归档到第二天会被合并进按天的大包，到时就不能直接分析了。

**`post-collect.py`**：
- 只接受本采集器的命名：`<run-id>_<节点>_ibdiagnet2.tgz` 或 `<run-id>_<节点>_iblinkinfo.log`。
- CVT 优先用当前 P2P 对应的 `<P2P 源文件名>-cvt.xlsx`；有多个时 fail closed。
- iblinkinfo 的 `.log` 直接交给分析器（`--iblinkinfo`），不再解包。
- 分析器非零退出、报告没生成，都算失败。
- **报告是否属于本轮看 provenance，不看修改时间**（owner 2026-10-22）：分析器写的 `<报告>.provenance.json` 里，报告、实际输入和 CVT 三者的 `sha256` 与 `resolved_path` 都必须对得上本轮的文件，否则失败，不写收据。
- **收据** `<报告名去掉 .xlsx>.receipt.json`（schema `ufm-ib-report-receipt-v1`）：`run_id`、`node`、`kind`、`degraded`（iblinkinfo 即降级）、`collector`（取自 `.done` 的 `rc`、`reason`、`hostname`）、输入、CVT、报告、provenance 各自的文件名和 sha256、`created_at`。收据只由 post-collect 写，其它脚本不依赖它（owner：不要耦合）。
- 不刷新页面。

**清单对齐**（IB、NVL、UFM 与 Ethernet 相同，`generate-monitor-html.py::align_with_inventory`）：
- 归档里已不在当前 CSV 的设备不显示。
- 只要有归档，CSV 中有、本批次没返回的设备就显示为缺失。
- CSV 文件不存在时保持归档原样。
- NVL 只做清单对齐。NVL 设备信息的解析和链路分析工具尚未规划。

**CVT 的来源**

**已定（owner 2026-10-21）**：CVT 放在项目的 `99-output-p2p`，与历史用法和 ETH 一致。由 load 照 ETH 的做法生成并校验。这条线不考虑 REQ7 的流程：REQ7 只是共用数据源的另一条线（见 14.6）。

**已实现（2026-10-21，测试见下）**：
1. **转换器** `ztp/config/nvos/template/P2P/p2p-to-validation.py`
   - `_project_p2p_cvt` 只放开 `DAY0-Prepare/<项目>/99-output-p2p/<名称>-cvt.xlsx` 这一种 DAY0 目标。其它 DAY0 路径，包括 `01-global.yaml`、`99-output-p2p/report.xlsx`、`99-output-p2p/sub/x-cvt.xlsx`、`99-output-ztp/x-cvt.xlsx`、项目根下的 `x-cvt.xlsx`，照旧拒绝。REQ7 的两条拦截测试原样通过。
   - 默认输出（不带 `--output`）时，先解析 setup 的 `output-p2p` 链接，再写入项目真实的 `99-output-p2p`。原因是发布时用 `O_NOFOLLOW` 持有输出目录，拒绝链接父目录。显式 `--output` 的行为不变。
   - 在 `nvos/template/P2P` 下直接运行、不带参数即可，所有输入都取自本目录（自包含）。
   - 测试：`test_ib_cvt_project_output.py`。
2. **load** `DAY0-Prepare/11-load.py::generate_configs`，在处理 nvos 的那一段：
   - 设备类型含 `ib`、且 deployment scope 不是 air 时，先在 `nvos/template/P2P` 下运行 `p2p-to-validation.py --expect-p2p-sha256 <本次 load 已校验的 P2P sha>`，再运行 `90-c2 --branch ib`。这对应 ETH 先跑 `b-xlsx_to_dot.py`、再生成配置。
   - `--expect-p2p-sha256` 是转换器的可选参数（2026-10-21 新增）：`p2p.xlsx` 的字节不是这个 sha 时不转换、不发布，退出码非 0，load 随之 `LoadError`。不带参数单独运行时行为不变，仍然满足自包含。
   - 与 ETH 对称：生成阶段只运行子进程，由子进程自己保证输入；provenance 的整体复核放在父 release 阶段（第二步）。
     - 最初版本把 `verify_ib_cvt` 放在 `generate_configs` 里。结果所有「把 `run` 换成假的、又没有 P2P 布局」的 load 测试（DHCP 两个 workflow 模块共 14 处）都 fail closed，这些测试与 CVT 无关。
     - ETH 的 splitter 校验也不在生成阶段，所以改成现在的做法。
   - `verify_ib_cvt(source_identities)` 已实现并有测试，留给第二步使用。它对应 ETH 的 splitter sidecar 检查：
     - `nvos/template/P2P/p2p.xlsx` 链接仍解析到生成 CVT 时用的那个 workbook；
     - 该 workbook 的 sha 等于 `source_identities["p2p"]`；
     - CVT 和 `.provenance.json` 都是单链接普通文件；
     - `read_cvt_provenance` 复核 6 个来源（P2P、inventory、port_map、splitter、converter、topology_rules）的当前字节，以及 CVT 自身的字节。
   - 只含 eth 或 nvl、或者 deployment scope 为 air 时不运行。
   - 转换器只对 `Protocol=unknown` 等情况给 WARNING、退出码仍为 0，load 沿用这个语义。
   - 测试：`test_load_ib_cvt.py`（命令与顺序、`verify_ib_cvt` 的各种拒绝情况）、`test_ib_cvt_project_output.py`（真实转换器：DAY0 窄放行、经链接写入、`--expect-p2p-sha256` 拒绝其它 P2P）。
3. **第二步（未做，待 owner 确认）**：照 ETH 的 `components.cumulus.splitter_provenance`，把 CVT provenance 写进父 release 的 `components.nvos`，并在 `commit_prepared_release` 前再复核。这会改变含 IB 设备的 `release_id`，需要同步不少既有测试。

**背景：原有的矛盾**（2026-10-21 核对，主仓库与沙箱相同；上面的放行解决了第 2 条中「生成」这一侧）：
- 原来没有任何生产脚本调用转换器。ETH 的 dot 是 `11-load.py` 调 `b-xlsx_to_dot.py` 生成的。
- 原有三处矛盾：
  1. setup（`tools/project_contract.py::P2P_OUTPUT_PATHS`）把 `nvos/template/P2P/output-p2p` 链接到 `DAY0-Prepare/<项目>/99-output-p2p`。
  2. REQ7（10-07）的转换器 `_reject_governed_cvt_output` 拒绝任何实际落在 `DAY0-Prepare/<项目>/` 下的输出，由下面两个测试固定：
     - `test_req7_ib_provenance.py::test_diagnostic_cvt_cannot_replace_day0_project_authority`
     - `test_req7_ib_provenance_workflow.py::test_real_cvt_cli_rejects_day0_project_path_even_when_child_links_out`
  3. REQ7 的 `monitor/collection_ib_producer.py:384-386` 要求 `output-p2p` 是固定目录、不能是链接。
  - 原结论：按原有代码，生产环境里 CVT 进不了 `99-output-p2p`。现在已由上面的窄放行解决。REQ7 的 IB producer 因为链接而 hold 属于 REQ7 自己的判断，这条线不动，已写入 14.6 的对接说明。
- **历史用法**（2026-10-21 实测）：`~/Desktop/http-test/DAY0-Prepare/2026-07-vb-gb300-staging/99-output-p2p/` 下有
  - `VisionBay Staging P2P v1.3-cvt.xlsx`（2026-08-14）；
  - `2026-0813-1530-iblinkinfo-topology-validation.xlsx`（2026-08-14）。

  CVT 和 IB 校验报告原来都放在项目的 `99-output-p2p`，与 Ethernet 的 dot 和报告一致。
  - 上面两处拦截最早出现在 `0be7bab`（2026-09-27 V3.1 快照），比这份 CVT 晚。
  - 这份旧 CVT 没有 `.provenance.json`，而现在的分析器（`validate_ib_topology.py::main` 调用 `read_cvt_provenance`）一定会校验 provenance，所以旧 CVT 必须重新生成才能用。
  - 它的文件名主干是「VisionBay Staging P2P v1.3」，而当前 `p2p.xlsx` 指向「…v1.3-DIY.xlsx」。`post-collect.py` 先找同名 CVT，找不到时如果只有一个 `*-cvt.xlsx` 就用它。
- **codex dev 最新 REQ7**（`~/Desktop/http`，`codex/v3.2-development` HEAD `16055ec`，2026-10-21 17:10）：
  - 转换器与沙箱的字节完全相同，拦截仍在；`collection_ib_producer.py:391-393` 的固定目录检查也仍在。
  - 近期 REQ7 提交集中在 issue tracker（Cable 同步、采集源适配器、completed-source read leases）。
  - 其中 `16055ec` 改了 `monitor/switch-collection-worker.py` 和 `monitor/switch_collection_gate.py`，与第 4.1 节「worker 计划 6 键」的改动区域重叠，集成时要三方合并（见第 14 节）。
- **测试覆盖说明**：转换器只保护它自己所在仓库的 `DAY0-Prepare`。
  - `test_ib_post_collect.py` 的端到端测试从真实仓库路径运行转换器，所以没有覆盖这道拦截。
  - `test_ib_cvt_project_output.py` 和 `test_load_ib_cvt.py` 把转换器复制到临时仓库里运行，拦截会真实生效。它们覆盖了「生产布局下，经 setup 链接写入项目 `99-output-p2p`」这条路径。

**真实环境待确认**：D-70 参数下，`/var/tmp/ibdiagnet2/` 里要有 `ibdiagnet2.net_dump`，分析器必需。确认方法：

```bash
docker exec ufm ls /var/tmp/ibdiagnet2/
```

**测试**：
- `test_ib_post_collect.py`：direct 测试；另有一个全真实的端到端测试，覆盖 P2P→CVT 转换器、UFM 格式的归档、分析器、页面读取。
- `test_ufm_monitor_cron_workflow.py`：先分析后刷新页面、分析失败只算 UFM 告警、没有归档时不分析。
- `test_monitor_ufm_status.py::IbInventoryAlignmentTest`：IB、NVL、UFM 的清单对齐。

## 14. 回归集成到 http 树（2026-10-21 起维护，owner：越详细越好）

### 14.1 沙箱基线与分歧
- 沙箱 `~/Desktop/ufm-setup` 的 git HEAD 是 `2644884`（来自 `~/Desktop/http-test`，2026-10-10，codex/v3.1-validation-export）。这个提交不在 `~/Desktop/http` 仓库里，不能直接用 `git merge-base`。
- 2026-10-21 用内容比对（沙箱 `HEAD:<path>` 对 http `HEAD:<path>`，http HEAD 为 `16055ec`）得到：沙箱改过的 45 个既有文件，http 自基线以来**全部也改过**，集成时都要三方合并，不能直接覆盖。复现脚本思路：对 `git status` 中每个非新增文件比较两边 `git show HEAD:<path>` 的 sha256。
- 新增文件（`??`）不存在冲突。2026-10-21 已核对，批次 B 的新文件在 http 中都没有同名文件。
- `test_cases/script_test_manifest.json` 必须手工合并：按条目合并 `scripts`、`test_rules`、`workflows`、`test_suites`，不能按 diff hunk 机械应用。

### 14.2 改动分批（按修改时间区分）
**批次 A：ufm-setup-upgrade 与 infra（2026-10-19 至 10-21 上午）**，说明见 `infiniband/bringup/ufm-setup-upgrade/README.md` 与 `infra/` 下的文档：
- UFM 部署工具：`infiniband/bringup/ufm-setup-upgrade/`；
- 主机公共模块：`infra/ubuntu24_host.py`，`infra/infra-setup.py`（取代 `infra-setup.sh` 作为入口）；
- 以及相应的 `tools/project_contract.py`、`tools/_package_common.py`、`DAY0-Prepare/02-unsetup.py`、`11-load.py` 等改动。
- 本节不展开批次 A。

**批次 B：UFM 监控、采集统一、IB 链路校验闭环（2026-10-21，本文档第 1–13 节）**，逐个文件如下。

| 文件 | 新增/修改 | 改了什么、为什么 | 对应测试 | http 是否已分歧 |
|---|---|---|---|---|
| `ethernet/monitor/cron.sh`（ib/nvl 目录下是指向它的链接） | 修改 | ① 新增 UFM 的 info、HA（经 VIP）、ibdiagnet 阶段，结果与交换机结果隔离（第 4、11 节）② 统一取回函数 `retrieve_when_ready`：先等 60 秒再每 5 秒轮询，取回先写到隐藏子目录，核对完成标记后改名 ③ 用管理口 MAC 核对身份，按设备类型提示输入密码 ④ worker 冻结计划改为 6 键（含 `ufm`）⑤ 只要采到数据就刷新页面 ⑥ IB 闭环：调用 `infiniband/monitor/post-collect.py` ⑦ 清理统计改用 `find -H` ⑧ `server_ufm` 行缺 IP 只跳过这台 | `test_ufm_monitor_cron_workflow`、`test_collector_retrieval`、`test_collector_publication`、`test_ufm_worker_collection`，以及已有的 cron 覆盖测试 | 否，可直接采用沙箱版本 |
| `ethernet/monitor/sw-info.sh`、`sw-link.sh` | 修改 | 临时目录改到输出目录下的隐藏目录，保证同一文件系统内原子改名；没发布任何东西时删除空的 `./monitor` | `test_collector_publication` | 否 |
| `infiniband/monitor/ufm-info.sh` | 新增 | 每台 UFM 的设备快照；`--ha` 模式只在主机上经 VIP 采 HA 状态与 sanity（第 4.2、8 节） | `test_ufm_monitor_scripts`、`test_ufm_monitor_cron_workflow` | 新文件 |
| `infiniband/monitor/ufm-ibdiagnet.sh` | 新增 | 在 VIP 主机上按 owner 的命令跑 ibdiagnet，用 run-id 命名，写完成标记；不带参数时自己生成 run-id，可单独运行（第 4.3 节） | `test_ufm_monitor_scripts` | 新文件 |
| `infiniband/monitor/post-collect.py` | 新增 | IB 链路校验闭环（第 13 节）。输入都取自本目录的链接：`ufm-ibdiagnet/`、`99-output-p2p/` | `test_ib_post_collect`（含真实端到端）、`test_ufm_monitor_cron_workflow` | 新文件 |
| `infiniband/monitor/UFM-MONITOR.md` | 新增 | 本文档 | `test_documentation_catalog` | 新文件 |
| `ethernet/monitor/README.md` | 修改 | 工作流、文件、自动分析边界、清单对齐、6 键计划等说明同步更新 | `test_documentation_catalog` | 否（2026-10-21 核对与基线相同） |
| `monitor/generate-monitor-html.py` | 修改 | ① UFM Servers 放在 IB 组最上面，列表仍是 21 列（第 12 节）② `.ha` 解析与主备健康度 ③ `align_with_inventory`：IB、NVL、UFM 按 ETH 规则对齐清单 ④ `extract_info_files` 增加 `suffix` 参数 | `test_monitor_ufm_status` | **是**，需三方合并 |
| `monitor/switch-collection-worker.py` | 修改 | 计划形状改为 6 键；`_collection_target_plan_matches_sources` 按冻结清单核对 `ufm` | `test_ufm_worker_collection` 和已有的 handoff 测试 | **是**：http `16055ec` 在同一文件新增 completed-source read leases |
| `monitor/collection_v2_emitter.py` | 修改 | 6 键；`ufm` 只能出现在 infiniband 槽位 | 同上 | 否 |
| `monitor/collection_ib_cycle_binding.py` | 修改 | 新增 `rebuild_ib_target_plan`，计划含 `ufm` 行 | `test_ufm_worker_collection` | 否 |
| `monitor/issue_tracker_switch_runtime.py` | 修改 | 两处计划构造补上 `"ufm": []` | `test_issue_tracker_switch_runtime(_workflow)` | **是** |
| `.dockerignore`、`infra/docker/.dockerignore`、`infra/docker/Dockerfile.dockerignore` | 修改 | 按 `tools/project_contract.py::image_host_state_docker_patterns` 重新生成 host-state 块（修正批次 A 手工追加的顺序） | `test_image_context_safety` | **是** |
| `user-manual.html` | 重新生成 | `tools/update-user-manual.py` 生成的目录 | `test_documentation_catalog` | **是**：合并后在 http 树里重新生成，不要手工合并 |
| `ztp/config/nvos/template/P2P/p2p-to-validation.py` | 修改 | 只放开 `<项目>/99-output-p2p/*-cvt.xlsx` 这一种 DAY0 目标（`_project_p2p_cvt`）；默认输出先解析 setup 的 `output-p2p` 链接；新增可选参数 `--expect-p2p-sha256`（第 13 节） | `test_ib_cvt_project_output`、REQ7 原有的 `test_req7_ib_provenance(_workflow)`（拦截测试原样通过） | 否 |
| `DAY0-Prepare/11-load.py` | 修改 | 新增 `IB_CVT_CONVERTER`、`_ib_topology_provenance`、`verify_ib_cvt`（留给第二步使用）；`generate_configs` 的 nvos 段在设备类型含 `ib` 时，先以 `--expect-p2p-sha256` 运行转换器（第 13 节） | `test_load_ib_cvt` | **是**，需三方合并（批次 A 也改了这个文件） |
| `ztp/config/nvos/template/README.md` | 修改 | 第 5 步补充 load 生成 CVT、落点、校验和单独运行方法 | `test_documentation_catalog` | 否 |
| `infiniband/monitor/ufm-ibdiagnet.sh`、`infiniband/monitor/post-collect.py` | 修改（自包含） | owner 2026-10-21「脚本要自包含，输入都在各自目录」：`ufm-ibdiagnet.sh` 不带参数时自己生成同格式的 run-id；`post-collect.py` 改读本目录的 `ufm-ibdiagnet/`、`99-output-p2p/`，不带参数时分析最新一份归档 | `test_ufm_monitor_scripts`、`test_ib_post_collect` | 新文件 |

**批次 B 新增的测试模块**：
- `test_ufm_monitor_scripts`
- `test_ufm_monitor_cron_workflow`
- `test_collector_publication`
- `test_collector_retrieval`
- `test_monitor_ufm_status`（含 `IbInventoryAlignmentTest`）
- `test_ufm_worker_collection`
- `test_ib_post_collect`

**批次 B 改动的他人测试**（断言语义未放宽，只改了 fixture 或预期，并写明理由）：
- `test_collection_cycle_handoff_workflow.py`：假采集器的 `.info` 补上 `# Collect complete`，与真实 `sw-info.sh` 一致。原因是取回端现在会核对完成标记。
- `test_issue_tracker_switch_runtime.py`、`test_issue_tracker_switch_runtime_workflow.py`、`test_collection_ib_producer_workflow.py`（2 处）、`test_collection_ib_cycle_binding_workflow.py`：手写计划补 `"ufm": []`。原因是计划改为 6 键（owner 选 A）。
- `test_project_contracts.py`：页面生成条件的钉值改为 `elif [[ -n "$INFO_ARCHIVE$LINK_ARCHIVE" ]] || (( UFM_COLLECTED )); then`。原因是 owner 要求「采到数据就刷新」。注意这个文件里还有批次 A 的 `infra-setup.py` 改动。
- `test_monitor_stack_review.py`：UTC 时间戳命名的计数从 6 改为 7（多了 UFM info）。
- `test_ztp_container_runtime.py`：已发布 Docker README 的大小和 sha256 钉值改为脚本按实际字节算出的值。原因是批次 A 把 README 的恢复命令改成了 `infra-setup.py --recover-monitor-authority --apply`，与 `infra/infra-setup.py::RECOVERY_COMMAND` 一致。**请 codex 评审时确认。**
- `test_ufm_monitor_scripts.py`、`test_monitor_ufm_status.py`（本批次新增）：随 owner 当天的新要求（HA 只经 VIP、脚本自包含）更新了预期。
- `test_load_release_transaction.py::test_switch_scope_is_forwarded_and_only_selected_generator_runs`：子命令带 `--switch` 的豁免名单从 `b-xlsx_to_dot.py` 扩大到 `p2p-to-validation.py`，并新增断言「只有 ib 范围运行转换器」。原因是 load 在 IB 上照 ETH 生成 CVT（owner 2026-10-21）。
- `test_generation_input_binding_workflow.py::test_real_nvos_scoped_generation_parent_remains_activatable`：执行过的子脚本列表在 ib 范围多了 `p2p-to-validation.py`。这个测试的 fixture 没有 P2P 布局，所以在这里不真的执行转换器，只记录它被调用、且参数只能是空或 `--expect-p2p-sha256`；真实转换器由 `test_ib_cvt_project_output`、`test_load_ib_cvt` 覆盖。nvl 范围不变。
- `test_load_release_transaction.py::test_scope_is_forwarded_to_every_generator_branch`：prod 下「每条子命令都带 `--deployment-scope`」的检查豁免转换器。原因是 CVT 没有环境维度（IB 只在 Production），新增断言 all/prod 会运行转换器、air 不运行。
- 未改动：DHCP 的两个 workflow 模块（`test_dhcp_optional_workflow`、`test_dhcp_switch_scope_preservation_workflow`）。改成由转换器自己校验以后，它们原样通过。

**manifest（`test_cases/script_test_manifest.json`）新增条目**：
- `scripts`：`infiniband/monitor/ufm-info.sh`、`ufm-ibdiagnet.sh`、`post-collect.py`
- `test_rules`：`ufm_monitor_collectors_direct`、`monitor_ufm_status_ui`、`ufm_worker_target_plan_direct`、`ib_post_collect_direct`
- `workflows`：`ufm_monitor_collection`、`ufm_worker_collection`、`ib_link_validation_closed_loop`
- `test_suites.monitoring-collection` 加入上述新测试模块；`shared_switch_collectors` 规则加入采集统一的两个测试
- load 与 CVT（2026-10-21 晚）：
  - `test_rules`：`ib_cvt_project_output_direct`（转换器）、`load_ib_expected_topology_direct`（11-load）
  - `workflows`：`load_ib_expected_topology`（11-load、转换器、`ib_topology_provenance.py`）
  - `test_suites.configuration-generation` 加入 `test_ib_cvt_project_output`、`test_load_ib_cvt`

**批次 C：HA 实测之后（2026-10-22）**。owner 当天在 ufm01/ufm02 上手工配好 HA，并把命令和输出记在 `ufm-manual.log`；本批次按这些实测结果修改。

| 文件 | 新增/修改 | 改了什么、为什么 | 对应测试 | http 是否已分歧 |
|---|---|---|---|---|
| `monitor/generate-monitor-html.py` | 修改 | ① `parse_ufm_ha_status` 读 Pacemaker 2 格式（`* Online:`、Promoted/Unpromoted、DRBD 行缩进且值带方括号）。修正前 DRBD 字段读不到、默认按正常处理，是静默漏判 ② `ufm_enterprise_sanity.sh` 未通过只在主机的 HA 详情末尾提示，不改变健康度（owner：status 是唯一依据）③ IB 口 LinkUp 但未 Active 且 `SM lid: 0` 时标注「SM 未分配 LID」 | `test_monitor_ufm_status`（20 项）、新增 `test_ufm_ha_status_parity` | **是**（同批次 B） |
| `infra/ubuntu24_host.py` | 修改 | 新增 `hosts_entries_script`：只追加缺少的 `/etc/hosts` 条目，不动已有行，改前备份（owner：「只需要新增后面两条」） | `test_ubuntu24_host`（2 项） | 批次 A 的文件 |
| `infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py` | 修改 | ① 配置步骤最后加 `hosts`：两台 UFM 按 HA 直连口（eno8403）地址写入 `/etc/hosts` ② `ha-setup` 实现 HA 配置：先读两台的 status，任何一台已有 HA 配置就不做任何配置（`HA_EXISTS`），最后提示先清除（owner 2026-10-22）；没有集群时确认一次，standby → master（带 VIP）→ 等 DRBD 同步 → start → 以 status 判定；配置输出写进设备上的日志（否则 `passwd` 的提示会让应答器中止会话）；sanity 只在运行最后提示 ③ `check` 的 `ha_config` 从固定的 `UNKNOWN` 改为按 status 判定；HA 已配置时跳过前提检查 ④ 完成状态只有 `HA_CONFIGURED` | `test_ufm_setup_upgrade`（新增 `HaStatusTest` 7 项、5 个假设备端到端用例）、新增 `test_ufm_ha_status_parity` | 批次 A 的目录 |
| `infiniband/bringup/ufm-setup-upgrade/README.md` | 修改 | `ha-setup` 全流程、状态、日志位置、未实测的推断（无集群/未启动时 status 的样子）、failover 后的读法 | `test_documentation_catalog` | 批次 A 的目录 |
| `ethernet/monitor/cron.sh` | 修改 | 兼容 UFM failover（owner 2026-10-22「代码要兼容 UFM failover 后 ssh 失败的情况」）：① 经 VIP 启动 HA 采集和 ibdiagnet 时，在同一个会话里读 `ip -br link`，按管理口 MAC 认出是 ib.csv 中的哪台；之后的轮询和取回都走这台自己的地址，不再走 VIP。原因：VIP 中途切换后，取回 HA 状态时可能拿到另一台以前当主机时留下的旧 `.ha`，ibdiagnet 则会白等到超时 ② UFM 的 ssh/scp（含公钥准备）加 `ServerAliveInterval=10`、`ServerAliveCountMax=3`，VIP 没人接管时 30 秒内发现。`deploy_ssh_keys` 加了可选的第 5 个参数，只有 UFM 传入，交换机不变 ③ 主机密钥本来就不固定（`UserKnownHostsFile=/dev/null`），VIP 换主机不影响登录 | `test_ufm_monitor_cron_workflow`（新增 3 项：HA 启动后切换、ibdiagnet 运行中切换、每个 UFM 会话都带保活；前两项已做变异验证：改回走 VIP 时失败） | 否 |
| `ethernet/monitor/cron.sh`（第二轮） | 修改 | owner 2026-10-22 定稿：① ibdiagnet/iblinkinfo 的等待改为启动后 5 分钟第一次探测、每 30 秒一次、最长 17 分钟（`UFM_IBDIAG_FIRST_WAIT/POLL/WAIT`）② 失败计数 `ufm-ibdiagnet/.ibdiagnet-state`：连续 3 次失败改采 iblinkinfo，每 6 轮再试 ibdiagnet，成功清零；去掉 `UFM_IBLINKINFO_FALLBACK` 开关③ 本地命名 `<run-id>_<节点>_ibdiagnet2.tgz` / `_iblinkinfo.log`，UFM 的 `.done` 一并保存④ `RETAIN_DAYS` 7 → 3；每日打包从只收 `*.tar.gz` 改为收所有以日期开头的文件（CSV 除外）⑤ 修复：删除超期文件的 `find` 没有 `-H`，数据目录是链接时从不删除（http HEAD 第 1800 行同样有此问题）⑥ `rotate_cron_log`：cronjob.log 到 10 MB 压缩，最多 7 个⑦ 采集锁被占用时日志写「上一轮采集仍在运行……本轮跳过」 | `test_ufm_monitor_cron_workflow`（新增 `UfmCronFabricModeAndRetentionTest` 6 项；保留期用例在加 `-H` 前失败、加后通过） | 否 |
| `infiniband/monitor/ufm-ibdiagnet.sh` | 修改（重写） | 按 owner 2026-10-22 的裁定和 `ufm-manual.log` 实测命令：① 两种模式：默认 ibdiagnet，`--iblinkinfo` 只跑 iblinkinfo（去掉同一轮内的回退）② 成功必须有本轮写出的 `ibdiagnet2.net_dump`，归档里也要有③ 在容器里用 `timeout -k 30 900` 运行（容器里有 `/usr/bin/timeout`），超时写进 reason④ 不用 `docker cp`：容器内打包到 `/opt/ufm/files`，主机上 mv 到 `/root/monitor/ibdiagnet/`（`UFM_HOST_FILES` 只供测试覆盖）⑤ 命名 `ibdiagnet2_<run-id>.tgz`、`iblinkinfo_<run-id>.log`⑥ iblinkinfo 只取 stdout（stderr 存 `.stderr`），上限 64 MiB⑦ `.done` 字段改为 `result/kind/run_id/artifact/sha256/size/rc/hostname/reason`⑧ INT/TERM 立即退出；锁目录无 pid 且不到 60 秒不当过期锁 | `test_ufm_monitor_scripts`（ibdiagnet 部分 14 项） | 新文件 |
| `infiniband/monitor/post-collect.py` | 修改 | ① 接受新命名，iblinkinfo 的 `.log` 直接分析② 报告是否属于本轮改用分析器的 provenance 核对（报告、输入、CVT 的 sha256 与路径），去掉按修改时间判断③ 写收据 `.receipt.json`（run-id、节点、是否降级、`.done` 里的退出码等） | `test_ib_post_collect`（9 项，含真实分析器端到端） | 新文件 |
| `infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py`（第二轮） | 修改 | owner 2026-10-22：HA 分成两块。① 新命令 `ha-post-config --apply`：只在已有且正常的 HA 上运行，经 VIP 安装 `*.lic`（工具目录 `image` 链接，主机从 `{common.mgmt.http}/image/` 下载，同名覆盖）、改 gv.cfg 的 `[Server]` 三项（其它字节不动，改前备份）、按 ibswitches 与 ib.csv 写 root_guid.conf（有 core 只写 core，否则 spine）；任一改动后只做一次 `ufm_ha_cluster failover`，再核对 status、`opensm-smdb.dump` 两行 smi、新主机 MAC 的 license 为 Valid ② `ha-setup` 新做完 HA 后自动调用它；已有 HA 时提示「清除后重跑，或确认正常后直接 ha-post-config」③ 登录 VIP 只接受两台各自的主机密钥（本次运行的 `vip-known-hosts`，`StrictHostKeyChecking=yes`），兼容 failover 后主机密钥变化 | `test_ufm_setup_upgrade`（新增 `HaPostConfigTest` 5 项、`HaPostConfigPureTest` 3 项；全流程用例改为接着 post-config 并 failover 到 ufm02） | 批次 A 的目录 |
| `ethernet/monitor/cron.sh`（第三轮） | 修改 | ① 交换机 info 归档和链路 CSV 改为先写 `.part` 再改名，与 UFM 文件一样「出现即完整」（给 REQ7 读）② `monitor/99-output-p2p` 里以日期开头的文件纳入 `cleanup_data_dirs` 的 3 天规则（CVT、P2P 生成物不受影响）③ 日志统一规则：`rotate_log` 用于各 lane 的 cronjob.log，以及 `monitor/generate-monitor.log`、`monitor/status/switch-collection.log`④ 共用目录与共用日志用一把非阻塞锁，同一时间只有一个 lane 处理 | `test_ufm_monitor_cron_workflow`（新增 2 项）；与采集相关的 13 个模块 578 项 | 否 |
| `monitor/generate-monitor-html.py`（第二轮） | 修改 | IB Link Validation 读到与报告字节一致的 `.receipt.json` 时，显示「采集：UFM <节点> · ibdiagnet/iblinkinfo（降级）· run-id」（`ufm_report_collection`）；收据不符或不存在则不显示 | `test_ib_post_collect`（真实分析器端到端用例里核对显示与不符时不显示） | **是**（同批次 B） |
| `infiniband/monitor/ufm-info.sh` | 修改 | 与上面相同的锁和 trap 修正（同一写法） | `test_ufm_monitor_scripts`（新增 2 项） | 新文件 |
| `test_cases/test_ufm_ha_status_parity.py` | 新增 | 工具与监控页面各有一份 status 解析（两边独立运行），用全部已记录的格式核对两边读出的字段相同 | 自身 | 新文件 |
| `ethernet/monitor/cron.sh`（第四轮，codex 评审 2026-10-22） | 修改 | ① 运行记录 `ufm-ibdiagnet/<run-id>.ufm-run.json`（schema `ufm-ib-run-record-v1`，`ufm_run_record_write`）：worker 周期身份（crontab 方式为 null）、`outcome` ok/failed/skipped、原因、本轮自己的 `.done`/输入/报告/收据（各为 name、sha256、size）、ibdiagnet 连续失败次数；先写 `.part` 再改名，是本轮最后写的文件。原因：REQ7 要能从周期找到这一轮，失败和跳过的运行不能被旧报告顶替 ② UFM 的 `.done` 不论成败都保存，失败的 `.done` 也是证据 ③ 取回的数据除 sha256 外再核对大小 ④ 数据、info 归档、链路 CSV 改用 `ln` 发布，同名已存在就失败，不覆盖 ⑤ 每日包加 `YYYYMMDD-daily.index`（每个成员的 sha256、大小、原名，成员平铺）：先打成 `.part`，核对成员后 `ln` 到最终名，再删原文件 ⑥ 采集失败的原因不再重复写退出码 | `test_ufm_monitor_cron_workflow`（新增 5 项：运行记录 ok/failed/skipped、worker 周期身份、同一分钟不覆盖；保留期用例加 index 核对）。worker 周期身份用例做过变异验证（`cycle` 写死为 None 时失败） | 否 |
| `infiniband/monitor/post-collect.py`（第二轮） | 修改 | 收据加 `done: {name, sha256}`，指向本轮的 `.done`；没有 `.done` 时为 null | `test_ib_post_collect` | 新文件 |
| `monitor/switch-collection-worker.py`（第二轮） | 修改 | 计划匹配器 `_collection_slot_artifacts_match` 接受加 `ufm` 键之前冻结的 5 键计划：没有 `ufm` 键时不检查 UFM 行，记录下来的摘要不重写。新冻结的计划仍必须是 6 键 | `test_ufm_worker_collection`（新增 5 键用例） | **是** |
| `monitor/collection_ib_cycle_binding.py`（第二轮） | 修改 | `inspect_completed_ib_cycle_roles`：信封的 `target_plan_sha256` 等于去掉 `ufm` 键的 5 键摘要时也接受。修正前，加 `ufm` 键之前完成的 IB 周期都会被判 HOLD | `test_collection_ib_cycle_binding_workflow`（新增 `test_a_cycle_frozen_with_the_five_key_plan_still_binds`，变异验证过：去掉兼容分支时报错） | **是**（REQ7 代码） |

| `ztp/config/cumulus/template/P2P/01-inventory.log` | 修改 | owner 2026-10-22：`[IB-SW]` 下加 `*ew-spine*`、`*ew-leaf*`。真实 P2P（B300 项目）的 IB 交换机叫 `ew-spineNNN` / `ew-leafNNN`，原有模式匹配不到，CVT 里会缺少全部交换机链路。同一理由，`[SMC-B300]` 下加 `*gpu-b300*`：GPU 改用 Hostname 列后叫 `suNN-gpu-b300l-NNN…`，原来会被 `*GPU*` 判成 GB300，8208 条 GPU 链路全部映射失败（实测）。其他项目的命名不在已有模式里时，也要照此加模式（写进了 `ztp/config/cumulus/README.md`） | 新增 `test_ib_cvt_project_output.py::ShippedInventoryRulesTest`，并登记到该文件的 path_rule；`test_topology_consistency` 与 path_rule 中原有的测试 | 否（http HEAD 与沙箱基线相同） |
| `ztp/config/nvos/template/P2P/p2p-to-validation.py`（第二轮） | 修改 | owner 2026-10-22：① 用 `02-devices_config.csv`（转换器目录下的 setup 链接，或 `--devices`）的设备名在 P2P 里找出名字列。每一侧允许 `name`、`Hostname` / `Host name` 连在一起，后面紧跟端口列；按第一段主机名、不分大小写匹配，命中最多的那一类列全表通用，GPU 也用它。没有该文件时用紧挨端口的那一列（原规则）② 提取到 0 条链路时报错，不发布 CVT（实测：原来会发布一个空 CVT，分析器把所有实际链路判为 Undefined 并照常出报告）③ 交换机或 UFM 的名字不在 `02-devices_config.csv` 里时给出警告（真实 P2P：`ufm-01`、`ufm-02`）④ 用到 `02-devices_config.csv` 时把它记进 CVT provenance。真实的 B300 P2P 不用改，已能生成 16852 条链路的 CVT（实测） | `test_ib_cvt_project_output.py::CvtDeviceNameColumnTest`（5 项，改前全部失败） | 是（同批次 B） |
| `ztp/config/ib_topology_provenance.py` | 修改 | CVT provenance 的来源角色除原来的 6 个外，可以多一个 `devices`（只允许这一个）；写入和读取两边都按此检查，旧的 6 角色 CVT 照样能读。**REQ7 读 CVT provenance 时要用这一版** | `CvtDeviceNameColumnTest`（含：多出未知角色时拒绝） | 是（REQ7 代码） |
| `tools/ibdiagnet-analyze-tool/lib/topology.py` | 修改 | `_actual_device_key_resolver`：实际名字与计划名字的第一段主机名相同、且只对应一个计划设备时，视为同一设备。原因：P2P 写 `ew-leaf001`，交换机报 `ew-leaf001.<域名>`，原来全部判为 Missing 加 Undefined。第一段主机名对应多台时不猜 | `test_ib_analysis_domain.py::FqdnDeviceNameTests`（2 项） | 否 |
| `ethernet/monitor/cron.sh`（第五轮，codex 第二轮评审） | 修改 | ① 共用的 `99-output-p2p` 加报告锁 `.report-writer.lock`（放在真实目录里）：两个 lane 的 post-collect 写报告时持共享锁（`with_report_writer`），清理持排它锁、不等待（`cleanup_shared_reports`）② 每日包已存在后才到的同日文件留在包旁边，日志写明，到期一起删除 ③ 修复：只剩每日包的旧日期永远不删（日期通配符要求横杠后是数字；基线与 http 都有） | `test_ufm_monitor_cron_workflow.py::UfmSharedReportCleanupTest`（4 项，改前全部失败） | 否 |
| `tools/log_rotation.py` | 新增 | owner 2026-10-22：谁写的日志谁负责轮转，轮转写成公共模块。规则：10 MB 时压缩成 `.1.gz` 后原地清空，最多 7 个；经链接时在真实文件旁轮转；先写好压缩副本再移位和清空，写副本失败时原文件不动。可以 import 使用，也有命令行入口 | 新增 `test_log_rotation.py`（6 项，改前全部失败）；登记为 `log_rotation_direct`，并加入 `ufm_monitor_collection` workflow | 新文件 |
| `ethernet/monitor/cron.sh`（第六轮） | 修改 | 只轮转自己写的 `cronjob.log`，并改为调用 `tools/log_rotation.py`；去掉对 `generate-monitor.log`、`switch-collection.log` 的轮转，以及只为它们设的 `with_shared_lock`。在 Docker 下，supervisord 本来就在轮转 `switch-collection.log`，原来两套机制管同一个文件 | `test_ufm_monitor_cron_workflow::test_cron_leaves_the_logs_other_scripts_write_to_them`（需求变化：原测试要求 cron.sh 轮转 `generate-monitor.log`，按 owner 新裁定改为不碰）；`cronjob.log` 的轮转测试不变 | 否 |
| `tools/collection_archive.py` | 新增 | owner 2026-10-22：采集信息目录的归档写成 `tools/` 下的模块，取代 `cron.sh` 里的 `cleanup_data_dirs` / `cleanup_bundle_day`，规则不变：当天原样；前几天按天打包，index 在前，CSV 不打包，`.part` 不碰，`.part` 核对后 link，已有的包不覆盖；迟到文件留在包旁边；超期的日期连同每日包和失败的批次目录一起删除；不跟随链接。`cron.sh` 通过它的命令行调用，并把输出的每一行写进本轮日志 | 新增 `test_collection_archive.py`（5 项，改前全部失败）；登记为 `collection_archive_direct`，并加入 `ufm_monitor_collection` workflow；`test_project_contracts::test_collection_retention_removes_only_expired_batch_directories` 原来从 cron.sh 里截取 bash 函数来测，改为调用模块，夹具和断言不变 | 新文件 |
| `ethernet/monitor/cron.sh`（第七轮） | 修改 | `cleanup_data_dirs` 改为调用 `tools/collection_archive.py`（约 110 行 bash 删去）；模块失败时只记 WARN，不影响采集结果 | `test_ufm_monitor_cron_workflow` 的保留期测试（夹具里加了 `.report-writer.lock` 的检查：它是隐藏的锁文件，不算数据） | 否 |
| `monitor/generate-monitor-html.py`（第三轮） | 修改 | `rotate_own_log()`：每次生成前、写第一行日志前，轮转自己的 `generate-monitor.log` | `test_log_rotation.py::test_the_page_generator_rotates_its_log_before_its_first_line` | **是** |
| `monitor/switch-collection-worker.py`（第三轮） | 修改 | `rotate_own_log()`：主循环每一轮检查一次，只有 stdout 就是 `monitor/status/switch-collection.log` 时（11-load.py 以追加方式打开）才轮转；Docker 下 stdout 是通向 supervisord 的管道，不动 | `test_log_rotation.py::test_the_worker_rotates_its_log_only_when_its_stdout_is_that_file` | **是** |
| `infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py`（第三轮） | 修改 | owner 2026-10-22：生成的脚本在发送前先在本地做 `bash -n` 语法检查（`bash_syntax_problem`），不通过就不发送，本地留下 not-run 副本（REQ-F01 10-12 合并需求第 3 条）。出厂默认密码保留字面量（owner 2026-10-22，取代 D-66 §二） | `test_ufm_setup_upgrade.py::ScriptLoaderTest::test_a_script_that_bash_cannot_parse_is_never_sent` | 批次 A 的目录 |
| `tools/collection_archive.py`（2026-10-23） | 修改 | owner 2026-10-23：「所有采集信息一定要留一份最新的散放；可以打包，但是不要删除掉最新的一份」。起因是现场只采 UFM 的一轮 cron 把前一天唯一的 IB 交换机归档打了包，页面只读散放的归档，于是看不到 IB 交换机。新增 `kind_of`、`newest_of_each_kind`、`bundled_index`：每类最新的一份照常进包但不删除、不过期；有了更新的一份后，与包内 index 一致的散放件删除，不一致的按迟到文件保留（见 4.4） | `test_collection_archive.py::test_the_newest_file_of_each_kind_always_stays_loose`（改前失败；7 个变异全部被杀）；`test_ufm_monitor_cron_workflow.py::UfmSharedReportCleanupTest::test_the_newest_switch_archive_stays_loose_for_the_page_after_a_ufm_only_run`（复现现场：只采 UFM 的 cron 之后，昨天的 IB 交换机归档仍散放） | 否 |

**最新一份散放（owner 2026-10-23）的测试预期变化**：以下 7 个用例里，被过期或打包的文件恰好是同类中唯一、也就是最新的一份。每个用例在夹具中补一份今天的同类文件，使被测文件不再是最新的。其余断言不变，只有两处目录清单随补的文件调整：`test_today_stays_previous_days_are_bundled_with_an_index_and_older_days_leave` 的预期清单加入今天的 `.done`；`test_dated_reports_in_99_output_p2p_follow_the_same_rule_and_the_cvt_stays` 像同组另一个用例一样，比较时排除今天的文件：
- `test_collection_archive.py`：`test_today_stays_previous_days_are_bundled_with_an_index_and_older_days_leave`、`test_a_late_file_stays_beside_the_bundle_and_a_day_kept_only_as_a_bundle_leaves`；
- `test_ufm_monitor_cron_workflow.py`：`test_everything_collected_is_kept_three_days_and_the_two_days_before_today_are_bundled`、`test_dated_reports_in_99_output_p2p_follow_the_same_rule_and_the_cvt_stays`、`test_the_cleanup_leaves_reports_alone_while_a_report_is_being_written`、`test_an_old_day_kept_only_as_a_bundle_is_deleted_with_its_late_files`；
- `test_project_contracts.py::MonitorContractTests::test_collection_retention_removes_only_expired_batch_directories`。

**codex 评审轮的测试预期变化**（需求变化：codex 2026-10-22 要求每轮留运行记录、每日包带 index）：
- 跳过用例：数据目录里除运行记录外不应有其它文件（原来是目录为空）。
- 保留期用例：每日包的成员多了 `YYYYMMDD-daily.index`，并逐行核对其内容；`99-output-p2p` 的每日包同样多了 index。

**批次 C 改动的测试预期**（需求变化：owner 给出了 HA 命令，HA 不再是「待实现」）：
- `test_ufm_setup_upgrade.py`：
  - `ha_config` 的预期从 `UNKNOWN` 改为 `WOULD_CHANGE`（2 处）；
  - `DONE_STATUSES["ha-setup"]` 从 `{"HA_READY"}` 改为 `{"HA_CONFIGURED"}`，退出码测试相应调整，并新增「`HA_READY`、`HA_EXISTS` 不是完成状态」；
  - 原「停止服务后做互信、到 `HA_READY` 为止」的用例改为全流程用例；
  - `hosts` 步骤加入 `CONFIG_STEPS`、`POST_UPGRADE_QUIET` 和两个 fixture 的 `/etc/hosts`。
- 假设备新增 `ufm_ha_cluster`（config/start/status）、`drbdadm status`、`ufm_enterprise_sanity.sh`、`nohup`、`timeout`。
- 新增断言：配置命令的完整参数与顺序（先 standby）、输出不回到会话、DRBD 等待与超时、已有 HA 配置（正常、未启动、异常、VIP 不符）一律不动并在最后提示清除、启动后 status 不正常判失败、sanity 只提示。

**manifest**：`test_ufm_ha_status_parity` 加入 `ufm_setup_upgrade_direct` 和 `monitor_ufm_status_ui` 两条规则，以及包含 `test_ufm_setup_upgrade` 的那个 suite。

### 14.3 setup 新增的链接（2026-10-22 已在 http 实现，见本节末尾）
| 链接 | 指向 | 使用者 |
|---|---|---|
| `infiniband/monitor/ufm-info` | `DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-info` | `cron.sh`（写入）、页面经 `monitor/infiniband/ufm-info` 读取 |
| `infiniband/monitor/ufm-ibdiagnet` | `…/99-output-monitor/infiniband/ufm-ibdiagnet` | `cron.sh`、`infiniband/monitor/post-collect.py` |
| `infiniband/monitor/01-global.yaml` | `../01-global.yaml`（与 `ib.csv` 同一模式） | `cron.sh` 读取 `servers.ufm.vip` |
| `infiniband/monitor/99-output-p2p` | `DAY0-Prepare/<项目>/99-output-p2p` | `infiniband/monitor/post-collect.py` 读取 CVT、写入 IB 报告 |
| `infiniband/bringup/ufm-setup-upgrade/image` | 管理服务器 http 树的 `image/` | `ufm-setup-upgrade.py ha-post-config` 在这里找 `*.lic`（owner 2026-10-22） |

这些链接还要同步加入：
- `tools/_package_common.py` 的打包清单；
- `test_cases/audit_public_tree.py` 的链接白名单；
- `DAY0-Prepare/02-unsetup.py` 的删除清单。

此外，setup/load 要接受 `server_ufm`、`server_mgmt` 两种 type（见 `infiniband/bringup/ufm-setup-upgrade/README.md`）。

**http 实现（2026-10-22，合入 http 时完成）**：都沿用 http 主线已有的机制，不另起炉灶。

| 链接 | 机制（`tools/project_contract.py`） | setup 中的创建点（`DAY0-Prepare/01-a-setup.py`） |
|---|---|---|
| `infiniband/monitor/ufm-info`、`ufm-ibdiagnet` | `NETWORK_MONITOR_SPECS` 的 infiniband 行加两个输出目录，经 `MONITOR_RUNTIME_MAPPINGS` 派生 | `_process_monitor_links`（同时创建项目下的目标目录） |
| `infiniband/monitor/01-global.yaml` | `MONITOR_RUNTIME_MAPPINGS`，别名指向 `infiniband/01-global.yaml`，链接文本 `../01-global.yaml` | `_process_monitor_links` |
| `infiniband/monitor/99-output-p2p` | `MONITOR_RUNTIME_MAPPINGS` | `_process_monitor_links` |
| `ufm-setup-upgrade/ib.csv`、`p2p.xlsx` | 新表 `BRINGUP_INPUT_SPECS`，指向 `infiniband/ib.csv`、`infiniband/p2p.xlsx`（链接文本 `../../ib.csv`、`../../p2p.xlsx`） | `_process_bringup_input_links` |
| `ufm-setup-upgrade/ufm-setup-upgrade-logs` | `BRINGUP_OUTPUT_SPECS` | `_process_bringup_links` |
| `ufm-setup-upgrade/image` | 新表 `BRINGUP_IMAGE_LINKS`（与项目无关，不进 `runtime_link_specs`；镜像构建由 `infiniband/bringup` 整棵子树排除） | `_process_bringup_image_links`：`http/image/` 不存在时跳过，不留断链 |
| `ufm-setup-upgrade/01-global.yaml`、`publickey` | git 跟踪的仓库桥接（`../../01-global.yaml`、`../../publickey`），与 xdr-initial-setup 相同；`test_cases/audit_public_tree.py::SETUP_RUNTIME_BRIDGES` 登记 | 不由 setup 创建，unsetup 也不删除 |
| `ztp/config/nvos/template/P2P/02-devices_config.csv` | `SETUP_ZTP_MAPPINGS`（转换器按清单设备名选 P2P 名称列） | 固定映射循环 |

- unsetup：`DAY0-Prepare/02-unsetup.py::_known_workspace_links` / `_known_ztp_project_links` 列出以上全部 setup 链接。
- 打包：`tools/_package_common.py::STATIC_SETUP_MANAGED_LINKS` 加 ufm-setup-upgrade 的六项。
- 忽略文件：`.gitignore` 手工加；三份 dockerignore 的 host-state 块按 `image_host_state_docker_patterns()` 重新生成。
- Docker：monitor 的四个链接进入 `published_runtime_link_specs()`，Docker 激活会逐个严格核对（必须存在、文本一致、落在当前项目）。**已部署的管理服务器升级到这一版后要重跑一次 setup**，否则激活会报 `published project link is missing`。
- 新 type：setup 的 `_validate_eth_csv` 接受两类，`server_ufm` 核对 eth0_ip（不带前缀）、netmask（可写 `/23`）、eth0_gw、eth0_mac（必填且不重复）；其余 10 个读 type 列的脚本跳过服务器行，`server_mgmt` 按 `server` 处理（`test_server_device_types`、`test_server_device_types_workflow`）。
- 测试：`test_setup_ufm_links_workflow`（setup → 每个链接的文本与解析目标 → unsetup 全部删除、桥接与项目数据不动；契约表、打包、审计）。

### 14.4 仍待决定或实测的事项
1. ~~CVT 放在哪里，load 是否生成 CVT~~：owner 2026-10-21 已定，放项目 `99-output-p2p`，load 生成并校验（已实现，第 13 节）。待定的只剩第二步：父 release 绑定和提交前复核。
2. **真实 UFM 上**：确认 ibdiagnet 产物里有 `ibdiagnet2.net_dump`；在 HA 配好的环境下跑一遍 `ufm-info.sh --ha`；结果登记到 `test_cases/REAL_ENVIRONMENT.md`。
3. 页面触发的自动采集（worker 路径）在真实 UFM 上走一遍。
4. **ibdiagnet 采集按 D-70 借鉴项修改（owner 2026-10-22 已裁定，已实施）**：
   - 已做（2026-10-22，见 14.2 批次 C）：
     - 没有 `ibdiagnet2.net_dump` 不算成功；
     - ibdiagnet 超时 15 分钟；
     - trap 收到 INT/TERM 要退出，pid 为空不当过期锁删除（`ufm-info.sh` 同样修正）。
   - 第二轮已做（owner 2026-10-22 答复后）：iblinkinfo 只取 stdout 并设 64 MiB 上限；IB 报告用 provenance 核对；本地收据；命名、等待、失败计数、保留期、cronjob.log 轮转（见 14.2 批次 C）。
   - 不做：运行前挪开旧的 `/var/tmp/ibdiagnet2`（ibdiagnet 自己会处理）；接收归档的大小上限。
   - SSH 的 `ServerAliveInterval`：建议只加在 UFM 的 ssh/scp 上。
   - failover 实测（`ufm-manual.log` 第 2001–2040 行）：
     - VIP 漂走后，旧会话立即收到 RST，不会一直挂住；只有 VIP 没有任何一台接管时，连接才会挂住。
     - `cron.sh` 已用 `UserKnownHostsFile=/dev/null`，VIP 主机密钥变化不影响采集。
     - 采集结果放在每台本机的 `/root/monitor/`。如果采集中途发生切换，这一轮取不到，记 UFM 警告，下一轮恢复。
5. **HA 之后的配置（owner 2026-10-22 在 ufm-manual.log 中补充，问题已列给 owner）**：全部经 VIP 操作。
   - license：有 `.lic` 时下载到 `/opt/ufm/files/licenses/`，否则只有评估 license；
   - `gv.cfg`：`multi_port_sm = ha_enabled`、`additional_fabric_interfaces`；
   - `root_guid.conf`：按 ibswitches 的 spine（大网络为 core）GUID 生成，缺少的 spine 在最后提示；
   - 任何一项有改动就 `ufm_ha_cluster failover`，再经 VIP 核对 HA、gv.cfg 和 license 是否生效。

### 14.5 建议的集成步骤
1. 在 http 树新开分支或 worktree（不要直接在 `codex/v3.2-development` 上改）。
2. 新增文件直接复制。
3. 「否」那一列的文件直接采用沙箱版本，复制前用 `git show HEAD:<path>` 确认 http 的版本仍等于沙箱基线。
4. 「是」那一列的文件，把沙箱相对其基线的 diff 用 `git apply -3` 应用，冲突逐个解决。`switch-collection-worker.py` 要与 `16055ec` 的改动合并。
5. 手工合并 manifest，再重新生成 `user-manual.html`。
6. 按 `AGENTS.md` 先跑变更感知测试，再跑全量证明。

### 14.6 给 REQ7（codex）的对接说明
依据 codex 的 `~/Desktop/cable-tracker-sync.md`（2026-10-21 18:31，基准 http `16055ec`）第 6 节「需要一起对齐的共享接口」。

分工（owner 2026-10-21 确认）：IB/UFM 采集之后有两条线，共用同一个数据目录。
- 展示线：本文档所述的分析、提取、页面展示。
- REQ7：分析、提取、本地 Issue Tracker、在线同步。

两条线互不读取对方的输出：REQ7 不读 HTML，展示线不碰 tracker。下表列出本批改动中**触及共享接口**的部分；纯展示改动（页面 UFM Servers、HA 显示、清单对齐等）不在表内，codex 文档也说明这类改动不需要 REQ7 同步修改。

| 共享接口（codex 文档 6.1–6.4） | 本批改动 | REQ7 需要做什么 |
|---|---|---|
| 6.4 共享 worker/gate 代码 | `monitor/switch-collection-worker.py` 的冻结计划从 5 键改为 6 键，新增 `ufm`（第 4.1 节）；`collection_v2_emitter.py` 同步修改 | 按新字节重新接收；与 `16055ec` 在同一文件的改动三方合并 |
| 6.4 `collection_ib_cycle_binding.py` | 新增 `rebuild_ib_target_plan`，IB 计划含 `ufm` 行（只取有 IP、非注释的 `server_ufm` 行，与 `cron.sh` 选法一致） | 重新验证 IB 周期读取 |
| REQ7 自身代码 `issue_tracker_switch_runtime.py` | 两处计划构造补 `"ufm": []`（只为匹配 6 键形状，语义不变） | 确认并接收 |
| 6.1 文件与角色：`expected_cvt` | CVT 改为由转换器写到**项目的 `99-output-p2p`**（owner 2026-10-21，与历史用法和 ETH 一致）。转换器只放开 `<项目>/99-output-p2p/*-cvt.xlsx` 这一种 DAY0 目标；默认输出时先解析 setup 的 `output-p2p` 链接，再按原来的防换目录机制写入。REQ7 的两条拦截测试不变 | `collection_ib_producer.py:391-393` 要求 `nvos/template/P2P/output-p2p` 不是链接，与 setup 的链接冲突（这是早就存在的矛盾，不是本批引入的）。是否改为接受「解析到当前项目 `99-output-p2p`」由 REQ7 决定 |
| 6.1 文件与角色：`validation_report` / `report_provenance` | 新增自动产生的 IB 校验报告：`99-output-p2p/<run-id>_<节点>-ibdiagnet-topology-validation.xlsx`（iblinkinfo 回退包为 `-iblinkinfo-…`），以及分析器写的 `.provenance.json`。由 `infiniband/monitor/post-collect.py` 调用**同一个** `tools/ibdiagnet-analyze-tool/analyze.py` 生成 | 报告结构（`Summary`、`Missing_Links`、`Miswired_Links` 等 sheet 和列名）来自同一个分析器，**未改动**。REQ7 是否把这些报告纳入它的九角色链，由 REQ7 决定 |
| 6.1 文件与角色：UFM 原件 | 新增共享上游数据：`monitor/infiniband/ufm-info/<UTC>.tar.gz`（每台 `<名称>.info`，以及经 VIP 采的 `<名称>.ha`），`monitor/infiniband/ufm-ibdiagnet/<run-id>_<节点>_ibdiagnet2.tgz`（成员为 `ibdiagnet2/ibdiagnet2.*`）或 `<run-id>_<节点>_iblinkinfo.log`（降级时），各带一份 `.done`。run-id 格式 `YYYYMMDD-HHMM-(prod|air)-<16 hex>` | 这是展示线的 shell 采集器（`cron.sh` 推送 `ufm-info.sh` / `ufm-ibdiagnet.sh`），与 D-70 的 `tools/ufm_collection_agent.py` 并存。REQ7 的 `ufm_actual_archive`、`ufm_completion_receipt` 角色目前仍来自 D-70 流水线（`99-output-ufm`）。owner 2026-10-22：D-70 废弃，REQ7 改读本线的数据，由 codex 迁移；约定（运行记录、`.done`、收据、每日包、6 键计划）见桌面《UFM-IB数据源与集成-给codex的对接文档》v2 |
| 6.3 完成与关联证据 | UFM 结果**不计入**交换机的 planned/succeeded/failed，也不进入 v2 证据计数；UFM 有问题时最后一行为 `cron finish with UFM warnings`，退出码不变 | 无需改动 |

**失败语义**（codex 文档要求提供）：
- 某台 UFM 采集失败：只记 UFM 告警，其余 UFM 和交换机照常进行。
- VIP 无应答（HA 未就绪）：ibdiagnet 和 HA 状态都记 SKIPPED，不算失败。
- IB 闭环分析失败（缺 CVT、分析器非零退出、报告没更新）：记 `[IB-CLOSED-LOOP] ERROR`，算 UFM 告警，页面照常刷新，不产生（或不更新）报告。

**一个完整合格周期的样例**：见 `test_cases/test_ib_post_collect.py::IbPostCollectRealAnalyzerWorkflowTest`。它用真实转换器、UFM 格式的归档和真实分析器跑通，结果为 Matching 1、PASS，报告文件名同上。cron 级别的样例见 `test_ufm_monitor_cron_workflow.py::test_the_fetched_ibdiagnet_archive_becomes_the_ib_link_validation_report_before_the_page`。

### 14.7 验证记录（沙箱，macOS，Python 3.9，2026-10-21 实测）
都是定向测试，不是全量证明。集成到 http 后，要按 `AGENTS.md` 重新跑变更感知测试和全量证明。

| 范围 | 结果 |
|---|---|
| 生成脚本、采集、UFM、IB 闭环相关模块（`test_monitor_ufm_status`、`test_ib_post_collect`、`test_project_contracts`、`test_monitor_stack_review` 等 12 个模块） | 536 个通过（1 skip）。另有 2 个文档目录测试失败，原因是手册没有重新生成；重新生成后通过 |
| UFM 脚本与 cron workflow（`test_ufm_monitor_scripts`、`test_ufm_monitor_cron_workflow`、`test_ib_post_collect`） | 40 个通过 |
| worker 6 键相关的全部 direct 和 workflow 测试（按 manifest 计算，共 60 多个模块） | 2570 个，其中 5 个失败。这 5 个都源自批次 A：`.dockerignore` 的顺序和 Docker README 的钉值，已修正；修正后那两个模块 316 个通过 |
| load 相关两个套件（`configuration-generation`、`deployment-runtime`）。这一轮用的是「`generate_configs` 内校验」的版本 | 4082 个，其中 16 个失败或报错，均为 fixture 没有 P2P 布局导致 fail closed |
| 改为「转换器以 `--expect-p2p-sha256` 自校验」之后，这 16 个所在的模块加 load、CVT 测试 | 56 个加 3 个，全部通过 |
| load 核心模块（`test_load_release_transaction`、`test_generation_input_binding_workflow`、`test_v2_generation_flow`、`test_flow_release_platform_matrix`、`test_load_ib_cvt`、`test_ib_cvt_project_output`） | 1097 个通过 |
| 文档目录与 manifest 治理（`test_documentation_catalog`、`test_change_aware_test_runner`） | 96 个通过 |
| 公开审计 `audit_public_tree.py` | 只剩批次 A 已知的 2 个 ufm-setup-upgrade 链接（沙箱没跑过 setup，链接目标不存在） |

**2026-10-22 批次 C 的验证记录（沙箱，macOS）**：

| 范围 | 结果 |
|---|---|
| `test_ufm_setup_upgrade` 整个模块（含新增的 HA 解析、HA 全流程、已有 HA 配置不处理等用例） | 176 个通过 |
| `test_ufm_ha_status_parity`、`test_monitor_ufm_status` | 22 个通过 |
| `test_ufm_monitor_scripts`（含 net_dump、超时、中断、加锁的新用例） | 24 个通过 |
| `test_ufm_monitor_cron_workflow` | 13 个通过 |
| `test_documentation_catalog` | 24 个通过 |
| manifest 校验（`ImpactManifestTests` 中的 suite 归属、direct/workflow 映射、目录检查） | 3 个通过 |
| 公开审计 | 只剩批次 A 已知的 2 个链接 |

### 14.8 全流程缺口清单（2026-10-22，owner 要求「整个流程需要完全打通」）

从 UFM 部署到页面展示，逐段列出现状与缺口。「待答」指等 owner 回复的问题。

| 环节 | 现状 | 缺口 |
|---|---|---|
| 1. 基本配置与升级（`config-upgrade`） | 已实现，假设备测试通过；ufm01/02 上手工走通 | `/etc/hosts` 步骤待真机跑一次 |
| 2. HA 部署（`ha-setup`） | HA 分成 `ha-setup` 和 `ha-post-config`（owner 2026-10-22）。ha-setup：已有 HA 配置时不做任何事，提示清除或改用 ha-post-config；否则 standby → master → 等同步 → start → status 判定，再自动 ha-post-config。ha-post-config：license、gv.cfg、root_guid.conf、failover、核对 | ① license 生效判定按 owner 描述实现，`ufmlicense` 的实际输出样本待 owner 提供后再核对 ② 真机运行记录在 owner 的 `ufm-manual.log` |
| 3. setup/unsetup/打包（codex） | 沙箱从未跑通 setup | **打通的头号阻断**：setup 要认 `server_ufm`/`server_mgmt`，并建好 14.3 的链接（如采用分目录，再加 `ufm-iblinkinfo`）。没有这些链接，`cron.sh` 的 UFM 阶段直接报 ERROR |
| 4. 采集（`cron.sh` + `ufm-info.sh` + `ufm-ibdiagnet.sh`） | info、HA（经 VIP）、ibdiagnet/iblinkinfo 都已接入；等待、失败计数与降级、命名、不用 docker cp、保留 3 天（含 99-output-p2p）、日志统一轮转、兼容 failover、所有归档和 CSV 先写 .part 再改名，都已按 owner 2026-10-22 的答复实现 | 磁盘：ibdiagnet 每份约 100 MB，10 分钟一轮时一天约 14 GB，3 天（当天原样加两个每日包）约 43 GB；每日包对已压缩的 .tgz 几乎没有压缩效果 |
| 5. 分析（`infiniband/monitor/post-collect.py`） | ibdiagnet 和 iblinkinfo 都能分析；报告用 provenance 核对；写收据；端到端测试通过 | 无 |
| 6. 页面（`generate-monitor-html.py`） | UFM Servers 在 IB 组最上面；IB Link Validation 显示最新报告和收据里的「哪一轮、哪台 UFM、是否降级」；owner 2026-10-22：不做单独的 UFM 页 | 页面 `import` 了 D-70 的 `tools.ufm_collection_pipeline`（第 59 行）和 UFM 证据面板，由 codex 废弃 D-70 时一并删除（已写进给 codex 的对接文档） |
| 7. REQ7（codex） | http `c250d17`：IB 数据只来自 D-70 自己的采集（worker 周期派生的 run_id、`99-output-ufm/runs/<run_id>/<node>/`、只认 iblinkinfo、归档成员必须叫 `artifact`、`ufm-collection-v1` 收据）；CVT 必须在不是链接的 `P2P/output-p2p/` 下；冻结计划没有 `ufm` | 与我们的数据源完全不对接。D-70 废弃后，REQ7 要改读我们的数据：由我们给出稳定约定（目录、命名、收据、报告和 provenance、CVT 位置），codex 改 REQ7。CVT 位置与 owner 定的 `99-output-p2p` 冲突，需 owner 与 codex 一起定 |
| 8. load 生成 CVT | 已做（转换器以 `--expect-p2p-sha256` 自校验） | 第二步（父 release 绑定、提交前复核）待决定 |
| 9. 回归 http 树 | 文档逐文件列明 | 45 个文件已与 http 分歧，需三方合并；http 今天又有多次 REQ7 提交（HEAD `c250d17`）|

## 15. REQ7 对接 R1：周期证据绑定新 UFM 链（2026-10-23，已在 http 实现）

owner 2026-10-22：「把落地代码合入 http，然后开始和 REQ7 对接」。codex 交接时的约定（`~/Desktop/codex-dev-handover.md` 第 11 节）：运行记录要绑定进 completion/emitter 证据；UFM 失败不能算进 REQ7 有效 K；D-70 先不删，迁移完依赖再退役。

**R1 做了什么**：REQ7 的本地 IB Cabling 不再必须依赖 D-70（`99-output-ufm`、root 授权与证明文件），可以改读本线的数据。

| 环节 | 文件::符号 | 行为 |
|---|---|---|
| 采集 | `ethernet/monitor/cron.sh`（`ufm_run_record_write`、v2 emitter 参数） | 本轮写了运行记录时，调用 emitter 带 `--ufm-run-record <记录>` |
| 绑定 | `monitor/collection_ufm_run_binding.py::derive_ufm_run_roles`（新增） | 只在「运行记录的 `cycle` 就是本周期、`outcome=ok`、`analysis=ok`」时绑定；逐个重读记录、`.done`、输入、报告、报告 provenance、收据、CVT 七个文件，名字与 SHA 层层对上，并用 `ib_topology_provenance.read_report_provenance` 重放报告与 CVT。路径一律是解析后的真实路径（`DAY0-Prepare/<项目>/…`），不穿过 setup 链接；项目由 `project_key` 核对 |
| emitter | `monitor/collection_v2_emitter.py::build_result`、`publish` | 能绑定时，IB slot 的证据为 3 个基础角色 + 7 个 UFM 角色，信封多一个 `ufm_run_binding`（run_id、node、kind、degraded、运行记录与收据的 SHA、CVT SHA）。**不能绑定时只写一行 stderr，IB slot 照常只有 3 个基础角色**——UFM 的问题（失败、跳过、不是本周期、模块缺失）都不改变交换机结果。与 D-70 的 `ib_analysis_binding` 互斥 |
| worker | `monitor/switch-collection-worker.py::_collection_slot_artifacts_match`、`_collection_validate_artifact_roles` | 信封带 `ufm_run_binding` 时，用同一个模块从文件重放，一致才接受，不信任信封 |
| REQ7 周期读取 | `monitor/collection_ib_cycle_binding.py::inspect_completed_ib_cycle_roles` | 新分支：重放后返回 `IbCycleRoleSource`（报告路径与 SHA、CVT SHA；`attestation_sha256` 位置放运行记录的 SHA），读前读后各重放一次 |
| REQ7 报告读取 | `monitor/issue_tracker_ib_runtime.py::read_completed_ib_cycle_report` | 报告在项目 `99-output-p2p/` 时，`recorded_at_utc` 取自 run-id 的 UTC 分钟 |

**测试**：
- `test_collection_ufm_run_binding`（direct，10 个）：正例、iblinkinfo 降级、经 setup 链接给出的记录、非本周期/失败/其他项目/不在采集目录、字节变化、收据不符、provenance 指向别的输入、重放篡改与穿链接、air 周期。
- `test_ufm_req7_ib_cycle_workflow`（workflow，3 个）：
  - 真实转换器、post-collect、分析器 → 真实 emitter 与 worker 核验 → 真实 completion → `inspect_completed_ib_cycle_roles` → `read_completed_ib_cycle_report`，读出 Missing 行；完成后改报告字节则 HOLD，worker 也拒绝；
  - UFM 运行不属于本周期：IB 只有基础角色（Gap），交换机周期仍 qualifying；
  - 真实 worker → 真实 cron.sh（假 UFM 跑出真实 ibdiagnet2 快照）→ post-collect → emitter：worker 接受带 10 个角色的 IB slot。
- 变异：删掉 cycle 检查、outcome 检查、provenance 输入检查、重放比较、emitter 绑定、worker 重放、读取分支、run-id 取时，各自都让上述测试变红。

**不在 R1、仍待处理**：
1. 在线 Cable 链 `monitor/issue_tracker_publish_runtime.py::_cable_hold_cycle_roles` 仍只认 D-70（授权文件、9 角色）——R2。
2. 退役 D-70：页面的 `tools.ufm_collection_pipeline` import 与 UFM 证据面板、`collection_ib_producer`、`monitor/99-output-ufm` 链接、`tools/ufm_collection_*`；`tools/ufm_collection_pipeline.py` 里被 REQ7 其他模块借用的持有 FD 辅助函数要先迁出——R3。
3. **待 owner 决定**：REQ7 的三面板资格目前是合在一起算的（`issue_tracker_stage_l_consumer.py::qualify_prod_stage_l`），IB 缺报告时 Switch、Eth 面板也一起 HOLD。是否改为按面板各自资格。
4. 跨午夜的 K 窗口：前一天的输入与报告被打进每日包后，旧周期重放失败，该窗口 IB HOLD（fail closed），每天一次、约 K 个周期；之后再加「散文件 + 每日包按 SHA 查」。
5. ~~已知旧问题~~ 已修（R0，2026-10-23）：旧的证据读取一律拒绝路径上的符号链接，而 setup 把 `<网络>/monitor/<输出目录>` 建成了指向项目的链接。实测（`collection_v2_emitter.regular_member` 探针）：经链接的路径被拒「traverses a symlink」，真实路径被拒「location is invalid」——真实管理服务器上 worker 每个 slot 的 v2 证据都会发布失败，REQ7 拿不到任何周期。修法：`tools/project_contract.py::setup_collection_link_hop` 只放行 setup 的采集输出链接本身（文本恰为 `../../DAY0-Prepare/<项目>/99-output-monitor/<网络>/<输出目录>`，目标沿途都是真实目录），emitter `regular_member`、worker `_collection_artifact_path`、REQ7 `issue_tracker_switch_runtime._safe_child` 都改用它，其它链接仍一律拒绝；证据字节仍由 SHA 绑定。测试 `test_setup_collection_link_evidence_workflow`（判定的放行/拒绝、三处读取、真实 emitter 与 completion 经链接完成并重放），5 个变异都让它变红。在线 Cable 链（R2）里的同类读取尚未改。
