import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def load(path):
    t, u = [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            t.append(float(row["time"]))
            u.append(float(row["usage_pct"]))
    return t, u

def align(t, u):
    t0 = next((a for a, b in zip(t, u) if b >= 60), 0)   # moment usage first reaches 60%
    return [a - t0 for a in t]

runs = [("Protection OFF", "results/fd_test2_attack_v2.csv"),
        ("Protection ON",  "results/fd_test4_protect.csv")]

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5), sharey=True)
for ax, (title, path) in zip(axes, runs):
    t, u = load(path)
    x = align(t, u)
    ax.plot(x, u, linewidth=2)
    for y, label in ((60, "Alert 60%"), (80, "Protect 80%"), (50, "Recover 50%")):
        ax.axhline(y, linestyle="--", linewidth=1, color="gray")
        ax.text(-9.5, y + 1, label, fontsize=8, color="gray")
    ax.set_title(f"{title} (peak {max(u):.1f}%)")
    ax.set_xlim(-10, 60)
    ax.set_ylim(0, 105)
    ax.set_xlabel("Seconds since usage first reached 60%")
axes[0].set_ylabel("Open-files usage (%)")
fig.suptitle("Open-files exhaustion attack: protection OFF vs ON")
fig.tight_layout()
fig.savefig("results/graph_files.png", dpi=150)
print("saved results/graph_files.png")
