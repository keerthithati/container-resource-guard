#!/usr/bin/env python3
import argparse, csv, glob, os, subprocess, time
from bcc import BPF

ALERT_T, PROTECT_T, RECOVER_T = 60.0, 80.0, 50.0   # percent

ap = argparse.ArgumentParser()
ap.add_argument("--no-protect", action="store_true", help="detect and alert only")
ap.add_argument("--free-hook", default="file_free", help="kernel function that releases a file")
ap.add_argument("--out", default="results/fd_run.csv")
args = ap.parse_args()

prog = r"""
#include <uapi/linux/ptrace.h>
BPF_PERCPU_HASH(net, u64, s64);     // cgroup id -> (files created - files released)

int ret_alloc(struct pt_regs *ctx) {
    unsigned long file = PT_REGS_RC(ctx);
    if (file >= (unsigned long)-4095) return 0;   // error code: nothing allocated
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v += 1; }
    return 0;
}
int on_free(struct pt_regs *ctx) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v -= 1; }
    return 0;
}
"""

def file_nr():  return int(open("/proc/sys/fs/file-nr").read().split()[0])
def file_max(): return int(open("/proc/sys/fs/file-max").read())
def docker(*a): return subprocess.run(["docker", *a], capture_output=True, text=True)

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
    print(f"   -> killing {name} to release its open files", flush=True)
    docker("kill", name)
    docker("start", name)

b = BPF(text=prog)
b.attach_kretprobe(event="alloc_empty_file", fn_name="ret_alloc")
hook = args.free_hook
try:
    b.attach_kprobe(event=hook, fn_name="on_free")
except Exception:
    print(f"could not hook {hook}, falling back to __fput", flush=True)
    hook = "__fput"
    b.attach_kprobe(event=hook, fn_name="on_free")

limit, base = file_max(), file_nr()
names, last = container_map(), time.time()
state, offender = "NORMAL", None
os.makedirs(os.path.dirname(args.out), exist_ok=True)
f = open(args.out, "w", newline=""); w = csv.writer(f)
w.writerow(["time", "state", "usage_pct", "files", "ebpf_net", "top", "top_net"])
t0 = time.time()
print(f"fd detector started: baseline={base} file-max={limit} free-hook={hook} "
      f"protection={'OFF' if args.no_protect else 'ON'}", flush=True)

try:
    while True:
        time.sleep(0.5)
        if time.time() - last > 3:
            try: names = container_map()
            except Exception: pass
            last = time.time()
        per = {}
        for k, leaf in b["net"].items():
            per[k.value] = sum(int(getattr(x, "value", x)) for x in leaf)
        used = file_nr()
        pct = 100.0 * used / limit
        cands = {k: v for k, v in per.items() if k in names}   # containers only
        top_id = max(cands, key=cands.get) if cands else None
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
                if not args.no_protect and offender == "attacker" and top_n > 0.3 * limit:
                    protect(offender)
            elif state == "RECOVER":
                offender = None

        w.writerow([f"{time.time()-t0:.2f}", state, f"{pct:.1f}", used, sum(per.values()), top, top_n])
        f.flush()
        print(f"{time.strftime('%H:%M:%S')} {state:8s} usage={pct:5.1f}% files={used:6d} top={top}({top_n:+d})", flush=True)
except KeyboardInterrupt:
    print("stopped")