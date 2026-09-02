# NVOS 配置生成工作目录

## 在整体架构中的位置

本目录复用 Cumulus 生成器实现并按 IB/NVL 类型分支，是统一项目输入到 NVOS 发布批次之间的
工作区。setup 管链接，load 管调用顺序，父目录发布器管 MAC/latest；本目录不直接启动服务或
连接设备。总体流程见根目录 `USER_MANUAL.md`。

本目录是 NVOS/InfiniBand/NVLink 配置生成的固定入口。它不复制生成器实现：
`90-c2-generate_configs.py` 指向 Cumulus template 中的共享生成器；setup 把 `01-global.yaml`、
`02-devices_config.csv` 和 `99-output-ib_nvl` 切换到当前项目。共享实现根据 device `type` 和
目标网络选择 NVOS 分支，因此两套网络不会维护两份漂移代码。

## 流程角色

1. setup 原子建立本目录输入/输出链接。
2. load 从本目录运行生成器，读取统一 global/devices。
3. 生成器按 `ib`、`nvl` 设备形成带时间戳批次并写入项目 `99-output-ib_nvl`。
4. NVOS `d-hostname2mac.py`（位于父目录、共享 Cumulus 发布实现）创建 MAC 发布链接并更新 latest。
5. `P2P/` 的 CVT、ibdiagnet 和 iblinkinfo 工具验证实际 fabric。

```bash
cd ztp/config/nvos/template
python3 90-c2-generate_configs.py --branch ib -y
```

直接执行前检查三个链接都属于同一项目。不要在本目录放真实项目数据或修改软链接指向；应通过
`DAY0-Prepare/01-a-setup.py` 切换。共享生成器变更必须同时回归 Cumulus 和 NVOS 测试。
标准路径内可省略 `--branch ib`，但 `11-load.py` 会明确传入；从临时目录运行共享脚本时必须
显式指定分支，无法可靠判断时脚本会报错而不是默认生成 IB 配置。
