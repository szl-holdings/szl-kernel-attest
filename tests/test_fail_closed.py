import json, unittest
from szl_kernel_attest.probe import probe, detect, SCHEMA

class TestFailClosed(unittest.TestCase):
    def test_detect_shape(self):
        env = detect()
        for k in ('kernel', 'bpftrace', 'uid', 'unprivileged_bpf_disabled', 'node'):
            self.assertIn(k, env)

    def test_receipt_schema_and_hash(self):
        r = probe(comm='python3', duration_s=1, burn=False)
        self.assertEqual(r['schema'], SCHEMA)
        self.assertIn('receipt_sha256', r)
        self.assertIsInstance(r['fail_closed'], bool)
        self.assertIn('joules', r['nvml'])

    def test_fail_closed_doctrine(self):
        # Doctrine: kernel claims are made ONLY when bpftrace actually observed
        # them. We cannot promise measurement success on any given host (CI
        # runners have bpftrace but restricted BPF), so the invariant is
        # CONSISTENCY + honest notes, never fabricated counts.
        env = detect()
        r = probe(comm='python3', duration_s=1, burn=False)
        self.assertEqual(r['fail_closed'], r['kernel_evidence'] is None)
        self.assertTrue(r['kernel_note'])
        if not env['bpftrace']:
            self.assertIsNone(r['kernel_evidence'])
            self.assertIn('bpftrace not found', r['kernel_note'])
        if r['kernel_evidence'] is not None:
            self.assertIsInstance(r['kernel_evidence']['sched_switch_events'], int)
            self.assertIn('bpftrace', r['kernel_evidence']['source'])

if __name__ == '__main__':
    unittest.main()
