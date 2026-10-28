#!/usr/bin/env python3
import glob, os, subprocess, time
from bcc import BPF

prog = r"""
#include <uapi/linux/ptrace.h>
BPF_PERCPU_HASH(net, u64, s64);     // cgroup id -> (files created - files released)

int ret_alloc(struct pt_regs *ctx) {            // runs when alloc_empty_file returns
    unsigned long file = PT_REGS_RC(ctx);
    if (file >= (unsigned long)-4095) return 0; // an error code: nothing was allocated
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v += 1; }
    return 0;
}

int on_fput(struct pt_regs *ctx) {              // runs when a file is released
    u64 cg = bpf_get_current_cgroup_id();
    s64 zero = 0;
    s64 *v = net.lookup_or_try_init(&cg, &zero);
    if (v) { *v -= 1; }
    return 0;
}
"""

def file_nr():  return int(open("/proc/sys/fs/file-nr").read().split()[0])
def file_max(): return int(open("/proc/sys/fs/file-max").read())

def container_map():
    out = subprocess.run(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"],
                         capture_output=True, text=True).stdout
    id2name = dict(l.split() for l in out.splitlines() if l.strip())
    paths = glob.glob("/sys/fs/cgroup/system.slice/docker-*.scope") + glob.glob("/sys/fs/cgroup/docker/*")
    names = {}
    for p in paths:
        cid = os.path.basename(p).replace("docker-", "").replace(".scope", "")
        if cid in id2name:
            names[os.stat(p).st_ino] = id2name[cid]
    return names

b = BPF(text=prog)
b.attach_kretprobe(event="alloc_empty_file", fn_name="ret_alloc")
b.attach_kprobe(event="__fput", fn_name="on_fput")

limit, base = file_max(), file_nr()
names, last = container_map(), time.time()
print(f"fd monitor started: baseline={base} files, file-max={limit}")

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
        top_id = max(per, key=per.get) if per else None
        top = names.get(top_id, "host/other") if top_id else "-"
        top_n = per.get(top_id, 0) if top_id else 0
        print(f"{time.strftime('%H:%M:%S')} files={used:6d} usage={pct:5.1f}% "
              f"delta={used-base:+6d} ebpf_net={sum(per.values()):+6d} top={top}({top_n:+d})", flush=True)
except KeyboardInterrupt:
    print("stopped")