# 架构与数据边界

## 一条端到端链路

项目电脑维护公共源码和规划输入，通过受控 upload/sync 写入管理服务器。管理服务器在统一部署
锁内完成项目激活、配置生成、parent/child release 校验和服务激活；交换机经 DHCP/HTTP 获取
bootstrap 与专属配置；监控将设备和服务证据写回项目输出；download/import 只把项目数据带回
项目电脑。代码下行和结果回流是两条不同的数据通道。

## 五类权威对象

| 对象 | 权威位置 | 规则 |
|---|---|---|
| 公共源码 | 项目电脑工作树 | 通过测试门禁和受控 writer 部署，不由现场归档反向覆盖 |
| 项目输入 | `DAY0-Prepare/<project>/` | setup/load 校验后使用，不与生成结果混放 |
| 共享制品 | `image/`、`apps/`、firmware | 以大小、摘要、平台和元数据绑定，不接受空占位作为 payload |
| 运行发布 | release manifest、MAC/latest 链接、DHCP staging | 只能由统一事务提交，失败保持旧代际或停止状态 |
| 项目证据 | `99-output-*`、日志、报告 | 通过 download/import 回收，不进入 upload 覆盖路径 |

## 两种服务后端

配置生成和 release 合同由公共生产代码共享，但服务生命周期只能选择一个后端：

- Native/systemd：宿主运行 `11-load.py`、Apache、ISC DHCP、cron/systemd worker。
- Docker/Supervisor：宿主只运行 `infra/docker/deploy.sh`，容器内由 Supervisor 管理五个业务服务。

同一轮部署不得混用两套生命周期命令。容器不会修改宿主 NIC、Netplan 或路由，也不会启用宿主
Apache/DHCP。详细选择和切换规则见[部署模式与受控发布](../deployment/README.md)。

## 身份与发布边界

IP 是传输端点，不是设备或环境身份。Production/AIR 可能复用地址；发布和采集还要绑定 scope、
hostname、完整 MAC、当前 release 和运行时 transport 接口。HTTP 静态边界只能减少误发布，
不能替代调用者认证、ACL 或 TLS；生产控制入口的真实认证由受控 vhost/反向代理提供。

源码更新、load/unload 和容器管理共用 `.deployment.lock`。任何源码 writer 必须先让受管容器
安全静止，再写入完整来源清单并提交 ownership/activation 状态；手工覆盖 live 树会破坏这一
因果链并被禁止。Docker writer 成功后还会提交 rebuild-required，下一步必须重新 deploy；
`load` 只保留给没有 source write 且受管容器仍在运行的 inactive/quarantine 恢复事务。同一
Service IP 在宿主接口间移动时使用 `reload-network → health → status`，不重新生成项目制品。
