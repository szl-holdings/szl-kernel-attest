# szl-kernel-attest: fail-closed ring-0 workload attestation.
# Kernel claims ONLY when bpftrace observed them; otherwise nulls + honest notes.
import hashlib, json, os, shutil, socket, subprocess, sys, time

SCHEMA = 'szl.kernel-attest/v1'

def _sysctl(name):
    try:
        with open('/proc/sys/' + name.replace('.', '/')) as fh:
            return fh.read().strip()
    except OSError:
        return None

def detect():
    uid = os.getuid() if hasattr(os, 'getuid') else -1
    sudo = None
    if uid != 0 and hasattr(os, 'getuid'):
        sudo = subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode == 0
    return {
        'kernel': _sysctl('kernel.osrelease'),
        'bpftrace': shutil.which('bpftrace'),
        'bpftool': shutil.which('bpftool'),
        'uid': uid,
        'passwordless_sudo': sudo,
        'unprivileged_bpf_disabled': _sysctl('kernel.unprivileged_bpf_disabled'),
        'node': socket.gethostname(),
    }

def _can_run_bpf(env):
    if not env['bpftrace']:
        return False, 'bpftrace not found'
    if env['uid'] == 0:
        return True, 'root'
    if env['unprivileged_bpf_disabled'] in ('0', None):
        return True, 'unprivileged bpf permitted'
    if env['passwordless_sudo']:
        return True, 'via passwordless sudo'
    return False, 'BPF is root-only (kernel.unprivileged_bpf_disabled=%s) and no passwordless sudo' % env['unprivileged_bpf_disabled']

def _bpftrace_count(bpftrace_path, comm, duration_s, use_sudo):
    prog = ('tracepoint:sched:sched_switch /comm == "%s"/ { @s = count(); } '
            'interval:s:%d { print(@s); exit(); }') % (comm, max(1, int(duration_s)))
    cmd = ((['sudo', '-n'] if use_sudo else []) + [bpftrace_path, '-q', '-e', prog])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_s + 40)
    except Exception as e:
        return None, 'bpftrace failed to run: %s' % str(e)[:120]
    val = None
    for tok in (p.stdout or '').replace('@s:', ' ').split():
        if tok.strip().isdigit():
            val = int(tok)
    if p.returncode != 0 or val is None:
        return None, 'bpftrace produced no parseable count (rc=%s)' % p.returncode
    return val, 'measured'

def probe(comm='python3', duration_s=5.0, burn=True):
    env = detect()
    ok, why = _can_run_bpf(env)
    burn_proc = None
    if burn:
        try:
            burn_proc = subprocess.Popen([sys.executable, '-c', 'x=0
while True: x+=1
'])
        except Exception:
            burn_proc = None
    joules = None
    nvml_note = 'pynvml unavailable or no GPU - no energy claim'
    nv = None
    h = None
    u0 = None
    try:
        import pynvml  # optional
        nv = pynvml
        nv.nvmlInit()
        h = nv.nvmlDeviceGetHandleByIndex(0)
        u0 = nv.nvmlDeviceGetTotalEnergyConsumption(h)
    except Exception:
        nv = None
    sched_events = None
    source = None
    note = why
    try:
        if ok:
            use_sudo = env['uid'] != 0 and env['unprivileged_bpf_disabled'] not in ('0', None)
            sched_events, n2 = _bpftrace_count(env['bpftrace'], comm, duration_s, use_sudo)
            source = 'bpftrace tracepoint:sched:sched_switch'
            note = (note + '; ' + n2) if sched_events is None else n2
        elif nv is not None:
            time.sleep(max(0.1, duration_s))
        if nv is not None:
            try:
                u1 = nv.nvmlDeviceGetTotalEnergyConsumption(h)
                joules = (u1 - u0) / 1000.0
                nvml_note = 'nvml device 0 total energy delta'
            except Exception as e:
                joules = None
                nvml_note = 'nvml read failed: %s' % str(e)[:120]
    finally:
        if burn_proc is not None:
            burn_proc.terminate()
            try:
                burn_proc.wait(timeout=5)
            except Exception:
                burn_proc.kill()
    fail_closed = sched_events is None
    receipt = {
        'schema': SCHEMA,
        'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'node': env['node'],
        'comm': comm,
        'duration_s': duration_s,
        'burn_spawned': burn_proc is not None,
        'environment': {
            'kernel': env['kernel'],
            'bpftrace_present': bool(env['bpftrace']),
            'uid': env['uid'],
            'unprivileged_bpf_disabled': env['unprivileged_bpf_disabled'],
            'passwordless_sudo': env['passwordless_sudo'],
        },
        'kernel_evidence': (
            {'sched_switch_events': sched_events, 'source': source} if sched_events is not None else None
        ),
        'kernel_note': note,
        'fail_closed': fail_closed,
        'nvml': {'joules': joules, 'note': nvml_note},
        'lambda': 'Conjecture 1 (advisory; trust never 100%)',
        'sovereign': False,
    }
    blob = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
    receipt['receipt_sha256'] = hashlib.sha256(blob.encode()).hexdigest()
    return receipt
