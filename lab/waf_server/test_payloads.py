# =============================================================================
# waf_server/test_payloads.py
# Script CLI test toàn bộ sample_payloads.json bằng cách gọi server qua HTTP.
# Dùng để xác nhận server hoạt động đúng + đo latency end-to-end (qua mạng).
#
# Chạy:    python test_payloads.py [--server http://127.0.0.1:8000] [--repeat 3]
# =============================================================================
import argparse
import json
import statistics
import time
from pathlib import Path
from urllib import request as urllib_request

THIS_DIR = Path(__file__).resolve().parent


def post_json(url: str, data: dict, timeout: float = 10.0) -> tuple[dict, float]:
    body = json.dumps(data).encode("utf-8")
    req = urllib_request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    t0 = time.perf_counter()
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read().decode("utf-8")
    elapsed = (time.perf_counter() - t0) * 1000
    return json.loads(payload), elapsed


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="http://127.0.0.1:8000")
    p.add_argument("--repeat", type=int, default=3,
                   help="Số lần lặp mỗi payload (mặc định 3)")
    args = p.parse_args()

    samples = json.loads((THIS_DIR / "sample_payloads.json").read_text(encoding="utf-8"))
    print(f"→ Test {len(samples)} payload qua {args.server}, mỗi cái {args.repeat} lần\n")

    confusion = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    e2e_times: list[float] = []
    server_times: list[float] = []
    rows = []

    for s in samples:
        for _ in range(args.repeat):
            try:
                data, e2e = post_json(args.server + "/predict", s["entry"])
            except Exception as exc:
                print(f"  ✗ {s['name']} → {exc}")
                continue
            e2e_times.append(e2e)
            server_times.append(data["timing_ms"]["total"])

            pred = 1 if data["is_attack"] else 0
            exp  = s.get("expected_label")
            if exp == 1 and pred == 1:   confusion["TP"] += 1
            elif exp == 0 and pred == 0: confusion["TN"] += 1
            elif exp == 0 and pred == 1: confusion["FP"] += 1
            elif exp == 1 and pred == 0: confusion["FN"] += 1

        rows.append({
            "name": s["name"],
            "category": s.get("category"),
            "expected": exp,
            "verdict": data["verdict"],
            "p": data["attack_probability"],
            "ms": data["timing_ms"]["total"],
            "e2e_ms": round(e2e, 2),
        })
        ok = "✓" if pred == exp else "✗"
        print(f"  {ok} [{data['verdict']:6s}] p={data['attack_probability']:.4f} "
              f"server={data['timing_ms']['total']:>6.2f}ms  e2e={e2e:>6.2f}ms  "
              f"— {s['category']:<14s} {s['name']}")

    def stats(arr):
        if not arr: return {}
        return {
            "min": round(min(arr), 2),
            "max": round(max(arr), 2),
            "mean": round(statistics.mean(arr), 2),
            "median": round(statistics.median(arr), 2),
            "p95": round(sorted(arr)[int(0.95 * (len(arr) - 1))], 2),
        }

    print("\n=== TIMING ===")
    print("Server-side (extract+predict):", stats(server_times))
    print("End-to-end (HTTP roundtrip):  ", stats(e2e_times))

    total_labelled = sum(v for v in confusion.values())
    if total_labelled:
        acc = (confusion["TP"] + confusion["TN"]) / total_labelled
        print(f"\n=== ACCURACY: {acc * 100:.2f}% ===  {confusion}")


if __name__ == "__main__":
    main()
