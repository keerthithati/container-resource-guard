#!/usr/bin/env python3
import argparse, csv, glob, os, subprocess, time
from bcc import BPF

ALERT_T, PROTECT_T, RECOVER_T = 60.0, 80.0, 50.0   # percent

ap = argparse.ArgumentParser()
ap.add_argument("--no-protect", action="store_true", help="detect and alert only")
ap.add_argument("--out", default="results/guard_run.csv")
args = ap.parse_args()

prog = r"""
#include <uapi/linux/ptrace.h>
BPF_PERCPU_HASH(pid_net, u64, s64);   // cgroup id -> tasks created - tasks exited
BPF_PERCPU_HASH(fd_net, u64, s64);    // cgroup id -> files allocated - files released

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = pid_net.lookup_or_try_init(&cg, &zero);
    if (v) { *v += 1; }
    return 0;
}
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = pid_net.lookup_or_try_init(&cg, &zero);
    if (v) { *v -= 1; }
    return 0;
}
int ret_alloc(struct pt_regs *ctx) {
    unsigned long file = PT_REGS_RC(ctx);
    if (file >= (unsigned long)-4095) return 0;   // error code: nothing allocated
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = fd_net.lookup_or_try_init(&cg, &zero);
    if (v) { *v += 1; }
    return 0;
}
int on_fput(struct pt_regs *ctx) {
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = fd_net.lookup_or_try_init(&cg, &zero);
    if (v) { *v -= 1; }
    return 0;
}
"""

def pid_max():    return int(open("/proc/sys/kernel/pid_max").read())
def proc_tasks(): return int(open("/proc/loadavg").read().split()[3].split("/")[1])
def file_max():   return int(open("/proc/sys/fs/file-max").read())
def file_nr():    return int(open("/proc/sys/fs/file-nr").read().split()[0])
def docker(*a):   return subprocess.run(["docker", *a], capture_output=True, text=True)

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

def protect_pids(name):
    print(f"   -> [pids] capping {name} at 50 processes and killing its processes", flush=True)
    docker("update", "--pids-limit", "50", name)
    docker("kill", name)
    docker("start", name)

def release_pids(name):
    print(f"   -> [pids] lifting the process cap on {name}", flush=True)
    docker("update", "--pids-limit", "100000", name)

def protect_files(name):
    print(f"   -> [files] killing {name} to release its open files", flush=True)
    docker("kill", name)
    docker("start", name)

def next_state(state, pct):
    if state == "NORMAL":
        if pct >= PROTECT_T: return "PROTECT"
        if pct >= ALERT_T:   return "ALERT"
    elif state == "ALERT":
        if pct >= PROTECT_T: return "PROTECT"
        if pct < ALERT_T:    return "NORMAL"
    elif state == "PROTECT":
        if pct < RECOVER_T:  return "RECOVER"
    elif state == "RECOVER":
        return "NORMAL"
    return state

b = BPF(text=prog)
b.attach_kretprobe(event="alloc_empty_file", fn_name="ret_alloc")
b.attach_kprobe(event="__fput", fn_name="on_fput")

def read_table(name):
    per = {}
    for k, leaf in b[name].items():
        per[k.value] = sum(int(getattr(x, "value", x)) for x in leaf)
    return per

RES = {
    "pids":  dict(table="pid_net", used=proc_tasks, limit=pid_max,
                  protect=protect_pids, release=release_pids),
    "files": dict(table="fd_net", used=file_nr, limit=file_max,
                  protect=protect_files, release=None),
}
for r in RES.values():
    r["state"], r["offender"] = "NORMAL", None

names, last = container_map(), time.time()
os.makedirs(os.path.dirname(args.out), exist_ok=True)
f = open(args.out, "w", newline=""); w = csv.writer(f)
w.writerow(["time", "resource", "state", "usage_pct", "used", "top", "top_net"])
t0 = time.time()
print(f"guard started: pid_max={pid_max()} file-max={file_max()} "
      f"protection={'OFF' if args.no_protect else 'ON'}", flush=True)

try:
    while True:
        time.sleep(0.5)
        if time.time() - last > 3:
            try: names = container_map()
            except Exception: pass
            last = time.time()
        parts = []
        for rname, r in RES.items():
            per = read_table(r["table"])
            used, limit = r["used"](), r["limit"]()
            pct = 100.0 * used / limit
            cands = {k: v for k, v in per.items() if k in names}   # containers only
            top_id = max(cands, key=cands.get) if cands else None
            top = names.get(top_id, "-") if top_id else "-"
            top_n = per.get(top_id, 0) if top_id else 0

            prev = r["state"]
            state = r["state"] = next_state(prev, pct)
            if state != prev:
                t = time.time() - t0
                print(f"[{t:7.1f}s] [{rname}] {prev} -> {state}  usage={pct:.1f}%  top={top}({top_n:+d})", flush=True)
                if state == "PROTECT":
                    r["offender"] = top
                    if not args.no_protect and top == "attacker" and top_n > 0.3 * limit:
                        r["protect"](top)
                elif state == "RECOVER":
                    if not args.no_protect and r["release"] and r["offender"]:
                        r["release"](r["offender"])
                    r["offender"] = None
            w.writerow([f"{time.time()-t0:.2f}", rname, state, f"{pct:.1f}", used, top, top_n])
            parts.append(f"{rname}={state}:{pct:5.1f}%({top}{top_n:+d})")
        f.flush()
        print(time.strftime("%H:%M:%S") + "  " + "  ".join(parts), flush=True)
except KeyboardInterrupt:
    print("stopped")