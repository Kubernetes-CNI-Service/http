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
   - 设备类型含 `ib` 时，load 在 IB 配置生成之前运行 `P2P/p2p-to-validation.py`（owner 2026-10-21，对应
     Ethernet 的 `cumulus/template/P2P/b-xlsx_to_dot.py`）。
   - 输出 `<P2P 源文件名>-cvt.xlsx` 加 `.provenance.json`，经 setup 的 `P2P/output-p2p` 链接写入项目的
     `99-output-p2p`，与 `<p2p>-lldpq.dot` 并列。
   - load 运行时传入 `--expect-p2p-sha256 <本次 load 已校验的 P2P sha>`，`p2p.xlsx` 不是这份字节时转换器不发布，load 失败。
     provenance 的整体复核（`11-load.py::verify_ib_cvt`）留给父 release 阶段。
   - 转换器只允许写项目 `99-output-p2p` 下的 `*-cvt.xlsx`，其它 DAY0 路径一律拒绝。
   - IB 闭环（`infiniband/monitor/post-collect.py`）用这份 CVT 校验 UFM 取回的 ibdiagnet。

   单独运行（自包含，所有输入都取本目录的链接）：

   ```bash
   cd ztp/config/nvos/template/P2P && python3 p2p-to-validation.py
   ```

```bash
cd ztp/config/nvos/template
python3 90-c2-generate_configs.py --branch ib -y
```

直接执行前检查三个链接都属于同一项目。不要在本目录放真实项目数据或修改软链接指向；应通过
`DAY0-Prepare/01-a-setup.py` 切换。共享生成器变更必须同时回归 Cumulus 和 NVOS 测试。
标准路径内可省略 `--branch ib`，但 `11-load.py` 会明确传入；从临时目录运行共享脚本时必须
显式指定分支，无法可靠判断时脚本会报错而不是默认生成 IB 配置。
