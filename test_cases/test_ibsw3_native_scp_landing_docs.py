"""Repository document contracts; no production import or device operation.

DOC_ROOT is the repository root containing this ordinary test module.
Private qualification must retain that same relative repository layout.
These literals describe the approved operator/field boundaries, not test counts.
"""
from pathlib import Path
import unittest


DOC_ROOT = Path(__file__).resolve().parents[1]
UPGRADE = Path('infiniband/bringup/xdr-upgrade')
LEGACY = '**以下正文保留旧 shell 版本历史，旧传输菜单、参数和输出目录不再是当前运行合同。**'


class NativeScpLandingDocumentationTests(unittest.TestCase):
    def test_current_operator_and_handoff_preserve_fixed_source_contract(self):
        readme = (DOC_ROOT / UPGRADE / 'README.md').read_text()
        self.assertEqual(readme.count(LEGACY), 1)
        current = readme.split(LEGACY)[0]
        handoff = (DOC_ROOT / UPGRADE / 'HANDOFF-CODEX-TEST.md').read_text()
        for document in (current, handoff):
            with self.subTest(document='README' if document is current else 'HANDOFF'):
                for literal in ('同批', '15 秒', '回车', 'HTTP', 'SCP', 'HTTPS',
                                'scp -O', '--scp-known-hosts', '--mgmt-server',
                                '--mgmt-user', '--mgmt-port', 'known_hosts',
                                '不 TOFU', '不换代', 'once-hash', '物理本机',
                                '数字签名', '第三方', 'CPLD 两包', '零 NV',
                                'SCP V2 ACK', 'file/dir fsync', 'finish/close',
                                'lease', 'public DATA', 'launch_payload',
                                'preflight_source', 'HOLD', 'OS 有序链', '金丝雀', '最终 OS',
                                'UNKNOWN', 'reset/adopt', 'argv', 'env'):
                    self.assertIn(literal, document)
        self.assertNotIn('当前仅支持 **HTTP** 包来源', current)
        self.assertNotIn('- 仅 HTTP 包来源；HTTPS、SCP、local 明确拒绝', handoff)
        self.assertIn('HTTP_POLICY', handoff)
        self.assertIn('HTTP is the default transfer; SCP requires explicit selection.', handoff)
        self.assertIn('HTTP mode does not fall back to SCP, HTTPS or local transport.', handoff)
        self.assertNotIn('其文案修正须另保', handoff)
        self.assertIn('不是当前合同', handoff)
        self.assertIn('共 19 个文件', handoff)
        self.assertIn('  ibsw_upgrade_scp.py\n', handoff)
        self.assertIn('fixtures/ibsw3-source-inverse/', handoff)
        self.assertIn('FROZEN_SHA256', handoff)

    def test_field_evidence_and_release_limits_are_not_promoted_to_acceptance(self):
        readme = (DOC_ROOT / UPGRADE / 'README.md').read_text().split(LEGACY)[0]
        handoff = (DOC_ROOT / UPGRADE / 'HANDOFF-CODEX-TEST.md').read_text()
        real = (DOC_ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text()
        heading = '## TC-IBSW3-NATIVE-SCP-LIFECYCLE-20261020 — NOT RUN'
        self.assertEqual(real.count(heading), 1)
        field = real.split(heading, 1)[1].split('\n##', 1)[0]
        for literal in ('适用 management-server/Linux/NVOS', '真实 SSH', '断电',
                        'NOT RUN', '维护授权', '回滚负责人', 'CPLD 两包', '零 NV',
                        'file/dir fsync', '关键 finish/close', '同 lease', 'SCP V2 ACK',
                        'HTTP V1', 'HTTP 200/curl', '不增加硬件/源版本兼容预检查',
                        '等长错误内容', '第二 CPLD 包失败', 'reserved marker',
                        'file-sync/dir-sync/关键 close', '本台 HOLD', '共享停批',
                        '中断与冷恢复', '清理与回滚', 'NOT_REACHED', 'FAIL/UNKNOWN',
                        'private NV fetch exit 93', '不是安装成功', 'full NOT RUN',
                        'load/sync/package', '治理阻塞', 'REQ7', 'OPEN', 'F01/UFM', 'STOP'):
            self.assertIn(literal, field)
        for document in (readme, handoff):
            self.assertIn('fetch exit 93', document)
            self.assertIn('不是安装成功', document)
            self.assertIn('未跑 full' if document is readme else 'full 未跑', document)
            self.assertIn('load/sync/package', document)
            self.assertIn('REQ7', document)
            self.assertIn('OPEN', document)
            self.assertIn('F01/UFM', document)
            self.assertIn('STOP', document)
        self.assertIn('Historical declaration-only source epoch', real)
        self.assertIn('At that DATA-only epoch CLI was HTTP-only', real)
        self.assertIn('13 项 PASS', handoff)
        self.assertIn('历史 13 项 PASS 不代表新增案例已执行', handoff)


if __name__ == '__main__':
    unittest.main()
