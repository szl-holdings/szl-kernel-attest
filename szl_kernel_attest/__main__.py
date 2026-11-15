import argparse, json
from .probe import probe

def main():
    ap = argparse.ArgumentParser(prog='szl-kernel-attest', description='Fail-closed ring-0 workload attestation probe')
    ap.add_argument('--comm', default='python3')
    ap.add_argument('--duration', type=float, default=5.0)
    ap.add_argument('--no-burn', action='store_true')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    r = probe(comm=a.comm, duration_s=a.duration, burn=not a.no_burn)
    s = json.dumps(r, indent=1, sort_keys=True)
    if a.out:
        open(a.out, 'w').write(s + '\n')
    print(s)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
