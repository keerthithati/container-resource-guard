import subprocess, time, os

name = os.environ.get("NAME", "victim")
ok = fail = 0
while True:
    t = time.time()
    try:
        subprocess.run(["true"], check=True)   # needs a new process
        f = open("/etc/hostname"); f.close()   # needs a file descriptor
        ok += 1
        status = "OK"
    except Exception as e:
        fail += 1
        status = "FAIL " + type(e).__name__
    lat = (time.time() - t) * 1000
    print(f"{time.strftime('%H:%M:%S')} {name} {status} latency_ms={lat:.1f} ok={ok} fail={fail}", flush=True)
    time.sleep(0.5)