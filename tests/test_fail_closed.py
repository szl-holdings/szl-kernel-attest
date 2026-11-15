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
        env = detect()
        r = probe(comm='python3', duration_s=1, burn=False)
        if not env['bpftrace']:
            self.assertIsNone(r['kernel_evidence'])
            self.assertTrue(r['fail_closed'])
            self.assertIn('bpftrace not found', r['kernel_note'])
        else:
            self.assertIsNotNone(r['kernel_evidence'])
            self.assertFalse(r['fail_closed'])
        if r['kernel_evidence'] is not None:
            self.assertIsInstance(r['kernel_evidence']['sched_switch_events'], int)

if __name__ == '__main__':
    unittest.main()
