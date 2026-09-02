# Test Case Template

新增功能、流程或场景时，先复制下面模板，再把可自动执行的部分实现到本目录的
`test_<area>.py`。同一个缺陷必须先有能稳定复现失败的案例，再提交修复。

## 基本信息

- Case ID：`TC-<MODULE>-<NNN>`
- 名称：
- 类型：unit / contract / transaction / integration / scenario / real-environment
- 对应需求或缺陷：
- 自动化文件与测试方法：
- 适用平台：local / management-server / Cumulus / NVOS / AIR

## 风险与目标

- 要防止的故障：
- 涉及的模块和状态边界：
- 成功标准：

## 前置条件与输入

- Fixture / 项目输入：
- 外部依赖：
- 所需权限：
- 初始状态：

## 步骤

1. （填写步骤）
2. （填写步骤）
3. （填写步骤）

## 预期结果

- 正向结果：
- 拒绝/失败结果：
- 不允许发生的副作用：
- 需要保存的证据：

## 故障注入与清理

- 并发、超时、异常、重启或输入篡改：
- 清理/回滚验证：
- 重复执行与幂等性：

## 自动化状态

- [ ] 已加入 `test_cases/test_<area>.py`
- [ ] 修复前能够稳定失败
- [ ] 修复后通过
- [ ] 已纳入全量 discovery
- [ ] 需要真机的部分已加入 `REAL_ENVIRONMENT.md`
