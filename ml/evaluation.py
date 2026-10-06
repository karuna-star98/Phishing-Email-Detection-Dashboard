"""Metrics + confusion-matrix plots. Every number is computed from real predictions - never typed in."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


def compute_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def plot_confusion_matrices(results: dict, path: str):
    """results: {name: metrics_dict}. Draws one matrix per detector (rows = actual, cols = predicted)."""
    n = len(results)
    cols = min(3, n)
    rows = -(-n // cols)
    fig, axes = plt.subplots(rows, cols, figsize=(4.2 * cols, 3.8 * rows))
    axes = axes.flatten() if n > 1 else [axes]
    for ax, (name, m) in zip(axes, results.items()):
        grid = [[m["tn"], m["fp"]], [m["fn"], m["tp"]]]
        ax.imshow(grid, cmap="Blues")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, grid[i][j], ha="center", va="center", fontsize=14,
                        color="white" if grid[i][j] > max(map(max, grid)) / 2 else "black")
        ax.set_xticks([0, 1], ["Legit", "Phish"])
        ax.set_yticks([0, 1], ["Legit", "Phish"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title(f"{name}\nP={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f}", fontsize=9)
    for ax in axes[n:]:
        ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
