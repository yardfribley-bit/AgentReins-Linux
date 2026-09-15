import unittest

from policy import compile_policy
from policy.agentspec import to_agentspec
from policy.ir import Action, Enforcement
from policy.validator import PolicyValidationError


TEXT = "监控 tat_agent 收到和执行的全部命令，记录它读取的文件和网络连接；修改系统文件时需要我确认；读取密码或凭据时立即阻止；记录 TLS 明文内容。"


class CompilerTests(unittest.TestCase):
    def test_observe_mode_rejects_blocking_policy(self):
        with self.assertRaises(PolicyValidationError):
            compile_policy(TEXT)

    def test_enforce_mode_compiles_tat_policy(self):
        policy = compile_policy(TEXT, mode="enforce")
        self.assertEqual(policy.scope.executable, "tat_agent")
        pairs = {(rule.action, rule.enforcement) for rule in policy.rules}
        self.assertIn((Action.PROCESS_EXEC, Enforcement.RECORD), pairs)
        self.assertIn((Action.FILE_WRITE, Enforcement.REQUIRE_APPROVAL), pairs)
        self.assertIn((Action.FILE_READ, Enforcement.DENY), pairs)
        self.assertIn((Action.NETWORK_CONNECT, Enforcement.RECORD), pairs)
        self.assertIn((Action.TLS_PLAINTEXT, Enforcement.RECORD), pairs)

    def test_agentspec_render_is_auditable(self):
        rendered = to_agentspec(compile_policy(TEXT, mode="enforce"))
        self.assertIn("trigger process_exec", rendered)
        self.assertIn("enforce user_inspection", rendered)
        self.assertIn("enforce stop", rendered)


if __name__ == "__main__":
    unittest.main()
