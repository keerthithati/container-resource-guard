import subprocess, sys, time

target = int(sys.argv[1])                                # how many processes to create
delay = float(sys.argv[2])                               # pause between each one (seconds)
hold = int(sys.argv[3]) if len(sys.argv) > 3 else 600    # how long to hold AFTER creating them

procs = []
for i in range(target):
    try:
        procs.append(subprocess.Popen(["sleep", "3600"]))
    except OSError as e:
        print("fork failed:", e, flush=True)
        break
    time.sleep(delay)

print(f"created {len(procs)} processes, holding {hold}s", flush=True)
time.sleep(hold)

for p in procs:
    p.kill()
for p in procs:
    p.wait()
print("done, all processes released", flush=True)