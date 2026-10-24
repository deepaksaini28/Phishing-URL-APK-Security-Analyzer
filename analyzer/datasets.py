import csv
import os


URL_DATASETS = {
    "Dataset.csv": {
        "url_column": "url",
        "label_column": "label",
        "label_note": "0 appears benign and 1 appears phishing based on inspected examples; source documentation was not supplied.",
        "trainable": True,
    },
    "urlset.csv": {
        "url_column": "domain",
        "label_column": "label",
        "label_note": "0.0 appears benign and 1.0 appears phishing based on inspected examples; 98 malformed rows were excluded from the inspected file.",
        "trainable": False,
    },
    "url_features_extracted1.csv": {
        "url_column": "URL",
        "label_column": "ClassLabel",
        "label_note": "Label direction is ambiguous from the file and examples; not used for training.",
        "trainable": False,
    },
}


def _csv_filenames(dataset_dir):
    try:
        return [name for name in os.listdir(dataset_dir) if name.lower().endswith(".csv")]
    except OSError:
        return []


def network_flow_csv_count(dataset_dir):
    return sum("pcap_ISCX" in name for name in _csv_filenames(dataset_dir))


def _summarize_csv(path, config):
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        headers = next(reader, [])
        label_index = headers.index(config["label_column"]) if config["label_column"] in headers else -1
        row_count = 0
        malformed = 0
        labels = {}
        for values in reader:
            row_count += 1
            if len(values) != len(headers):
                malformed += 1
                continue
            label = values[label_index].strip() if label_index >= 0 else ""
            if label:
                labels[label] = labels.get(label, 0) + 1
    return {
        "file": os.path.basename(path),
        "headers": headers,
        "rows": row_count,
        "malformed_rows": malformed,
        "labels": labels,
        **config,
    }


def inspect_datasets(dataset_dir):
    summaries = []
    for filename, config in URL_DATASETS.items():
        path = os.path.join(dataset_dir, filename)
        if os.path.isfile(path):
            try:
                summaries.append(_summarize_csv(path, config))
            except OSError as exc:
                summaries.append({"file": filename, "error": str(exc), **config})

    files = _csv_filenames(dataset_dir)
    flow_files = [name for name in files if "pcap_ISCX" in name]
    return {
        "url_datasets": summaries,
        "network_flow_csv_count": len(flow_files),
        "other_csv_count": max(0, len(files) - len(flow_files) - len(URL_DATASETS) - 1),
        "apk_training_available": False,
        "note": "Network-flow CSVs describe captured traffic and cannot train a model on APK static features.",
    }
