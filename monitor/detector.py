#!/usr/bin/env python3
import argparse, csv, glob, os, subprocess, time
from bcc import BPF

ALERT_T, PROTECT_T, RECOVER_T = 60.0, 80.0, 50.0   # percent

ap = argparse.ArgumentParser()
ap.add_argument("--no-protect", action="store_true", help="detect and alert only")
ap.add_argument("--out", default="results/pid_run.csv")
args = ap.parse_args()

prog = r"""
BPF_PERCPU_HASH(net, u64, s64);

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v += 1; }
    return 0;
}
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v -= 1; }
    return 0;
}
"""

def pid_max():   return int(open("/proc/sys/kernel/pid_max").read())
def proc_tasks(): return int(open("/proc/loadavg").read().split()[3].split("/")[1])
def docker(*a):  return subprocess.run(["docker", *a], capture_output=True, text=True)

def container_map():
    out = docker("ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}").stdout
    id2name = dict(l.split() for l in out.splitlines() if l.strip())
    paths = glob.glob("/sys/fs/cgroup/system.slice/docker-*.scope") + glob.glob("/sys/fs/cgroup/docker/*")
    names = {}
    for p in paths:
        cid = os.path.basename(p).replace("docker-", "").replace(".scope", "")
        if cid in id2name:
            names[os.stat(p).st_ino] = id2name[cid]
    return names

def protect(name):
    print(f"   -> capping {name} at 50 processes and killing its processes", flush=True)
    docker("update", "--pids-limit", "50", name)
    docker("kill", name)
    docker("start", name)

def release(name):
    print(f"   -> lifting cap on {name}", flush=True)
    docker("update", "--pids-limit", "100000", name)

b = BPF(text=prog)
baseline, limit = proc_tasks(), pid_max()
names, last = container_map(), time.time()
state, offender = "NORMAL", None
os.makedirs(os.path.dirname(args.out), exist_ok=True)
f = open(args.out, "w", newline=""); w = csv.writer(f)
w.writerow(["time", "state", "usage_pct", "ebpf_tasks", "proc_tasks", "top", "top_net"])
t0 = time.time()
print(f"detector started: baseline={baseline} pid_max={limit} protection={'OFF' if args.no_protect else 'ON'}")

try:
    while True:
        time.sleep(0.5)
        if time.time() - last > 3:
            try:
                names = container_map()
            except Exception:
                pass          # PID table full: keep the old container names
            last = time.time()
        per, total_net = {}, 0
        for k, leaf in b["net"].items():
            n = sum(int(getattr(x, "value", x)) for x in leaf)
            per[k.value] = n
            total_net += n
        total = baseline + total_net
        pct = 100.0 * total / limit
        top_id = max(per, key=per.get) if per else None
        top = names.get(top_id, "host/other") if top_id else "-"
        top_n = per.get(top_id, 0) if top_id else 0

        prev = state
        if state == "NORMAL":
            if pct >= PROTECT_T: state = "PROTECT"
            elif pct >= ALERT_T: state = "ALERT"
        elif state == "ALERT":
            if pct >= PROTECT_T: state = "PROTECT"
            elif pct < ALERT_T: state = "NORMAL"
        elif state == "PROTECT":
            if pct < RECOVER_T: state = "RECOVER"
        elif state == "RECOVER":
            state = "NORMAL"

        if state != prev:
            t = time.time() - t0
            print(f"[{t:7.1f}s] {prev} -> {state}  usage={pct:.1f}%  top={top}({top_n:+d})", flush=True)
            if state == "PROTECT":
                offender = top
                if not args.no_protect and offender in ("attacker",) and top_n > 0.3 * limit:
                    protect(offender)
            elif state == "RECOVER" and offender and not args.no_protect:
                release(offender)
                offender = None

        w.writerow([f"{time.time()-t0:.2f}", state, f"{pct:.1f}", total, proc_tasks(), top, top_n])
        f.flush()
        print(f"{time.strftime('%H:%M:%S')} {state:8s} usage={pct:5.1f}% ebpf={total:5d} top={top}({top_n:+d})", flush=True)
except KeyboardInterrupt:
    print("stopped")