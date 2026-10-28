#!/usr/bin/env python3
import glob, os, subprocess, time
from bcc import BPF

# ---------- kernel side (eBPF) ----------
prog = r"""
BPF_PERCPU_HASH(net, u64, s64);   // cgroup id -> (tasks created - tasks exited)

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

# ---------- user side (Python) ----------
def pid_max():
    return int(open("/proc/sys/kernel/pid_max").read())

def proc_tasks():   # independent cross-check, straight from /proc
    return int(open("/proc/loadavg").read().split()[3].split("/")[1])

def container_map():   # cgroup id -> container name
    out = subprocess.run(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"],
                         capture_output=True, text=True).stdout
    id2name = dict(l.split() for l in out.splitlines() if l.strip())
    paths = glob.glob("/sys/fs/cgroup/system.slice/docker-*.scope") + glob.glob("/sys/fs/cgroup/docker/*")
    names = {}
    for p in paths:
        cid = os.path.basename(p).replace("docker-", "").replace(".scope", "")
        if cid in id2name:
            names[os.stat(p).st_ino] = id2name[cid]   # cgroup id == directory inode
    return names

b = BPF(text=prog)
baseline = proc_tasks()   # tasks that already existed before we started counting
limit = pid_max()
names = container_map()
last = time.time()
print(f"monitor started: baseline={baseline} tasks, pid_max={limit}")

try:
    while True:
        time.sleep(0.5)
        if time.time() - last > 3:
            names = container_map()
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
        print(f"{time.strftime('%H:%M:%S')} ebpf_tasks={total:5d} proc_tasks={proc_tasks():5d} "
              f"usage={pct:5.1f}%  top={top}({top_n:+d})", flush=True)
except KeyboardInterrupt:
    print("stopped")