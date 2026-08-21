#!/usr/bin/env python3
"""Train the Sentry payload-anomaly model (classic ML -> ONNX).

Reads a CSV produced by `sentry model export` (columns: the Rust
FEATURE_NAMES + `label`), trains a logistic regression, evaluates on a
holdout split and exports an ONNX model that `sentry` loads behind the
`onnx` feature.

Feature extraction happens exclusively in Rust (`sentry-ai/src/features.rs`);
this script only consumes the exported vectors, so training and inference
can never drift apart. The header check below fails loudly if the two
sides get out of sync.

Usage:
    python tools/train_model.py --csv dataset.csv --out models/anomaly_v1.onnx

Requirements (see tools/requirements.txt):
    pip install -r tools/requirements.txt
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

# MUST match `sentry_ai::features::FEATURE_NAMES` (order and spelling).
FEATURE_NAMES = [
    "path_len",
    "query_len",
    "path_depth",
    "path_digit_ratio",
    "path_special_ratio",
    "path_entropy",
    "path_encoded_count",
    "path_dot_dot",
    "path_null_byte",
    "sqli_token_score",
    "xss_token_score",
    "traversal_token_score",
    "jndi_token",
    "cmd_token_score",
    "has_file_ext",
    "ext_is_script",
    "ext_is_sensitive",
    "method_is_get",
    "method_is_post",
    "ua_len",
    "ua_is_empty",
    "ua_bot_token",
    "status_4xx",
    "status_5xx",
    "query_param_count",
]


def load_csv(path: Path) -> tuple[list[list[float]], list[int], list[str]]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        expected = FEATURE_NAMES + ["label"]
        if header != expected:
            missing = set(expected) - set(header)
            extra = set(header) - set(expected)
            raise SystemExit(
                f"CSV header does not match the Rust FEATURE_NAMES.\n"
                f"  missing: {sorted(missing)}\n  extra: {sorted(extra)}\n"
                f"  Re-export with a matching `sentry model export` build."
            )
        rows: list[list[float]] = []
        labels: list[int] = []
        for line in reader:
            if not line:
                continue
            rows.append([float(v) for v in line[:-1]])
            labels.append(int(line[-1]))
    return rows, labels, header[:-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path, help="training CSV from `sentry model export`")
    parser.add_argument("--out", type=Path, default=Path("models/anomaly_v1.onnx"), help="output ONNX path")
    parser.add_argument("--test-size", type=float, default=0.25, help="holdout fraction")
    args = parser.parse_args()

    try:
        from skl2onnx import to_onnx
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report, roc_auc_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as e:
        print(f"missing dependency: {e}\n  pip install -r tools/requirements.txt", file=sys.stderr)
        return 1

    import numpy as np

    x, y, names = load_csv(args.csv)
    if len(set(y)) < 2:
        print("dataset has a single class — need both benign and malicious rows", file=sys.stderr)
        return 1

    x = np.asarray(x, dtype=np.float32)
    y = np.asarray(y, dtype=np.int64)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=args.test_size, random_state=42, stratify=y
    )

    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    )
    model.fit(x_train, y_train)

    proba = model.predict_proba(x_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print(classification_report(y_test, pred, target_names=["benign", "malicious"]))
    print(f"holdout AUC: {roc_auc_score(y_test, proba):.4f}")
    print(f"rows: train={len(y_train)} test={len(y_test)} features={len(names)}")

    # Export the full pipeline (StandardScaler + LogisticRegression) as ONNX
    # with a single float tensor input; the Rust side feeds raw 0..1 features.
    # `zipmap: False` keeps probabilities as a plain float tensor instead of
    # a sequence of maps, which is what the Rust extractor expects.
    onnx_model = to_onnx(
        model,
        x_train[:1].astype(np.float32),
        target_opset={"": 17},
        options={id(model): {"zipmap": False}},
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(onnx_model.SerializeToString())
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")

    # Quick import sanity check.
    try:
        import onnx

        m = onnx.load(str(args.out))
        onnx.checker.check_model(m)
        print("onnx checker: OK")
    except ImportError:
        print("onnx package not installed — skipped model check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
