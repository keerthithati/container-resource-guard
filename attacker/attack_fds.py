import os, resource, sys, time

target = int(sys.argv[1])                                # how many files to open
delay = float(sys.argv[2])                               # pause between opens (seconds)
hold = int(sys.argv[3]) if len(sys.argv) > 3 else 600    # how long to hold the table full

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

fds, full = [], False
for i in range(target):
    try:
        fds.append(os.open("/dev/null", os.O_RDONLY))
    except OSError as e:
        print("open failed:", e, flush=True)
        full = True                      # the system-wide table is full
        break
    if delay:
        time.sleep(delay)

print(f"opened {len(fds)} files, holding {hold}s", flush=True)

if full:
    # keep grabbing every slot that frees up, so the table stays full
    end, grabbed = time.time() + hold, 0
    while time.time() < end:
        try:
            fds.append(os.open("/dev/null", os.O_RDONLY))
            grabbed += 1
        except OSError:
            time.sleep(0.0005)
    print(f"re-grabbed {grabbed} freed slots during the hold", flush=True)
else:
    time.sleep(hold)

for fd in fds:
    os.close(fd)
print("done, all files released", flush=True)