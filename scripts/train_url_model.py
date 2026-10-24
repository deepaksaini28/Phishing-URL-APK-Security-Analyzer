import argparse
import csv
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit


def normalize_domain(value):
    candidate = value.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host or "invalid-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_examples(path):
    labels_by_url = {}
    duplicate_rows = 0
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = {field.strip().lower(): field for field in (reader.fieldnames or [])}
        url_field = fields.get("url")
        label_field = fields.get("label")
        if not url_field or not label_field:
            raise ValueError("Expected a URL column named 'url' and a label column named 'label'.")
        for row in reader:
            url = (row.get(url_field) or "").strip()
            label = (row.get(label_field) or "").strip()
            if url and label in ("0", "1"):
                if url in labels_by_url:
                    duplicate_rows += 1
                labels_by_url.setdefault(url, set()).add(label)
    conflicting_urls = {url for url, labels in labels_by_url.items() if len(labels) > 1}
    examples = [(url, next(iter(labels))) for url, labels in labels_by_url.items()
                if len(labels) == 1]
    return examples, duplicate_rows, len(conflicting_urls)


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate the local URL model on Dataset.csv.")
    parser.add_argument("--dataset", default=os.path.join("Dataset", "Dataset.csv"))
    parser.add_argument("--model-dir", default="models")
    args = parser.parse_args()

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (classification_report, confusion_matrix,
                                     precision_recall_fscore_support)
        from sklearn.model_selection import GroupShuffleSplit
        from sklearn.pipeline import Pipeline
        import joblib
    except ImportError as exc:
        print(
            "scikit-learn dependencies are unavailable or their native extensions could not be loaded. "
            "Install requirements.txt in a supported Python environment and retry.",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    examples, duplicate_rows, conflicting_urls = load_examples(args.dataset)
    if len(examples) < 100:
        raise SystemExit("Not enough labelled URL records to train.")
    urls = [item[0] for item in examples]
    labels = [item[1] for item in examples]
    groups = [normalize_domain(url) for url in urls]

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_indices, test_indices = next(splitter.split(urls, labels, groups))
    y_train = [labels[index] for index in train_indices]
    y_test = [labels[index] for index in test_indices]
    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        raise SystemExit("Group-aware split did not include both labels in train and test.")

    model = Pipeline([
        ("url_char_ngrams", TfidfVectorizer(analyzer="char", ngram_range=(3, 5),
                                            min_df=2, max_features=250000, sublinear_tf=True)),
        ("classifier", LogisticRegression(class_weight="balanced", max_iter=1000,
                                          random_state=42)),
    ])
    x_train = [urls[index] for index in train_indices]
    x_test = [urls[index] for index in test_indices]
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, labels=["0", "1"], zero_division=0
    )
    report = {
        "dataset": os.path.basename(args.dataset),
        "unique_urls_after_exact_deduplication": len(urls),
        "duplicate_rows_removed": duplicate_rows,
        "conflicting_label_urls_removed": conflicting_urls,
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "split": "80/20 GroupShuffleSplit by normalized hostname; random_state=42",
        "class_weight": "balanced",
        "classes": {"0": "appears benign from inspected examples", "1": "appears phishing from inspected examples"},
        "precision": {"0": float(precision[0]), "1": float(precision[1])},
        "recall": {"0": float(recall[0]), "1": float(recall[1])},
        "f1": {"0": float(f1[0]), "1": float(f1[1])},
        "macro_precision": float((precision[0] + precision[1]) / 2),
        "macro_recall": float((recall[0] + recall[1]) / 2),
        "macro_f1": float((f1[0] + f1[1]) / 2),
        "confusion_matrix_labels_0_1": confusion_matrix(y_test, predictions, labels=["0", "1"]).tolist(),
        "classification_report": classification_report(y_test, predictions, labels=["0", "1"],
                                                       zero_division=0, output_dict=True),
        "limitations": [
            "Label semantics are inferred from examples because source documentation was not supplied.",
            "An offline, group-aware evaluation does not guarantee performance on current threats.",
            "URL text does not provide live site reputation or page content.",
        ],
    }
    os.makedirs(args.model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(args.model_dir, "url_model.joblib"))
    with open(os.path.join(args.model_dir, "url_model_evaluation.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps({key: report[key] for key in
                      ("train_rows", "test_rows", "macro_precision", "macro_recall",
                       "macro_f1", "confusion_matrix_labels_0_1")}, indent=2))


if __name__ == "__main__":
    main()
