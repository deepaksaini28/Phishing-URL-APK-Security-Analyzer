const $ = (selector, root = document) => root.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
let toastTimeout;
let processedImageUrl;

function notify(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast visible${error ? " error" : ""}`;
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove("visible"), 3500);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(body?.error || body?.message || `Request failed (${response.status}).`);
  return body;
}

function setBusy(form, busy, label) {
  const button = $("button[type=submit]", form);
  button.disabled = busy;
  form.setAttribute("aria-busy", String(busy));
  $(".button-label", button).textContent = busy ? label : button.dataset.idleLabel;
  $(".spinner", button).hidden = !busy;
}

document.querySelectorAll("form").forEach(form => {
  $(".button-label", form).dataset.idleLabel = $(".button-label", form).textContent;
});

function resultCard(data) {
  const card = el("article", "result-card");
  const header = el("div", "result-header");
  const title = el("div");
  title.append(
    el("h3", "", data.classification || `${data.risk} risk`),
    el("p", "", data.subject || "")
  );
  const badge = el("span", `risk-pill risk-${(data.risk || "").toLowerCase().replaceAll(" ", "-")}`, data.risk || "Reviewed");
  header.append(title, badge);
  card.append(header);

  if (Number.isFinite(data.score)) {
    const score = el("div", "score-row");
    const track = el("div", "score-track");
    const fill = el("div", `score-fill ${data.score >= 55 ? "high" : data.score >= 25 ? "medium" : ""}`);
    fill.style.width = `${Math.max(0, Math.min(100, data.score))}%`;
    track.append(fill);
    score.append(track, el("span", "score-value", `Signal score ${data.score}/100`));
    card.append(score);
  }

  const metadata = data.metadata || {};
  const fields = data.kind === "apk"
    ? [
        ["Package", metadata.package],
        ["Version", metadata.version_name],
        ["SHA-256", data.sha256],
        ["Permissions", metadata.permissions?.length],
        ["Signing schemes", signingSchemes(metadata.signing_info)]
      ]
    : [
        ["Domain", data.domain],
        ["Protocol", data.scheme?.toUpperCase()],
        ["Local model", data.model_probability == null ? "Not configured" : `${Math.round(data.model_probability * 100)}% estimated phishing likelihood`]
      ];
  const meta = el("dl", "result-meta");
  fields.forEach(([label, value]) => {
    if (value === undefined || value === null || value === "") return;
    const item = el("div", "meta-item");
    item.append(el("dt", "", label), el("dd", "", String(value)));
    meta.append(item);
  });
  if (meta.childElementCount) card.append(meta);

  if (data.kind === "apk" && data.indicator_assessment) {
    const assessment = el("dl", "result-meta apk-assessment");
    Object.entries(data.indicator_assessment).forEach(([name, value]) => {
      const item = el("div", "meta-item");
      item.append(el("dt", "", name.replaceAll("_", " ")), el("dd", "", value));
      assessment.append(item);
    });
    card.append(assessment);
  }

  if (data.kind === "apk" && metadata.signing_info?.certificates?.length) {
    metadata.signing_info.certificates.forEach(certificate => {
      const item = el("p", "certificate-note",
        `Signer: ${certificate.subject || "Subject unavailable"} · SHA-256 ${certificate.sha256 || "unavailable"}`);
      card.append(item);
    });
  }

  const findings = el("ul", "finding-list");
  (data.findings || []).forEach(finding => {
    const row = el("li", "finding");
    row.append(el("span", `finding-mark ${finding.severity || "info"}`), el("span", "", finding.message));
    findings.append(row);
  });
  if (findings.childElementCount) card.append(findings);

  if (data.limitations?.length) {
    const limitations = el("p", "limitations", data.limitations.join(" "));
    card.append(limitations);
  }

  const actions = el("div", "result-actions");
  const csvReport = el("button", "button button-secondary", "Download CSV report");
  csvReport.type = "button";
  csvReport.addEventListener("click", () => downloadCsvReport(data));
  actions.append(csvReport);
  if (data.id) {
    const report = el("button", "text-button", "Download report");
    report.type = "button";
    report.addEventListener("click", () => downloadReport(data.id));
    actions.append(report);
  }
  card.append(actions);
  return card;
}

function downloadCsvReport(data) {
  const metadata = data.metadata || {};
  const fields = [
    ["Scan type", data.kind],
    ["Subject", data.subject],
    ["Risk", data.risk],
    ["Classification", data.classification],
    ["Signal score", data.score],
    ["Scan time", data.created_at || new Date().toISOString()],
    ["SHA-256", data.sha256],
    ["Domain", data.domain],
    ["Protocol", data.scheme],
    ["Package", metadata.package],
    ["Version", metadata.version_name],
    ["Permissions", metadata.permissions?.join(", ")],
    ["Signing schemes", data.kind === "apk" ? signingSchemes(metadata.signing_info) : undefined],
    ["Estimated phishing likelihood", data.model_probability == null ? undefined : `${Math.round(data.model_probability * 100)}%`]
  ].filter(([, value]) => value !== undefined && value !== null && value !== "");
  (data.findings || []).forEach((finding, index) => {
    fields.push([`Finding ${index + 1} (${finding.severity || "info"})`, finding.message]);
  });
  (data.limitations || []).forEach((limitation, index) => {
    fields.push([`Limitation ${index + 1}`, limitation]);
  });

  const escapeCsv = value => {
    let text = String(value);
    if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replaceAll('"', '""')}"`;
  };
  const csv = ["Report field,Value", ...fields.map(row => row.map(escapeCsv).join(","))].join("\r\n");
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  const filename = String(data.subject || data.kind || "scan")
    .replace(/[^a-z0-9_-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64) || "scan";
  link.download = `${filename}-report.csv`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function signingSchemes(signingInfo) {
  if (!signingInfo) return "Not decoded";
  const schemes = Object.entries(signingInfo.schemes || {})
    .filter(([, present]) => present)
    .map(([name]) => name);
  return schemes.length ? schemes.join(", ") : signingInfo.is_signed === false ? "None detected" : "Not decoded";
}

function showResult(slot, data) {
  slot.replaceChildren(resultCard(data));
}

function showError(slot, message) {
  const error = el("p", "form-error", message);
  slot.replaceChildren(error);
}

function showProgress(slot, message) {
  const progress = el("p", "progress-message");
  progress.setAttribute("role", "status");
  progress.setAttribute("aria-live", "polite");
  progress.append(el("span", "spinner spinner-dark"), document.createTextNode(message));
  const track = el("div", "scan-progress-track");
  track.setAttribute("aria-hidden", "true");
  track.append(el("span", "scan-progress-indicator"));
  const container = el("div", "scan-progress");
  container.append(progress, track);
  slot.replaceChildren(container);
}

$("#url-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const slot = $("#url-result");
  setBusy(form, true, "Analyzing…");
  showProgress(slot, "Scanning URL structure and domain indicators…");
  try {
    const result = await requestJson("/api/scan/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: $("#url-input").value,
        save_history: localStorage.getItem("saveUrlHistory") !== "false"
      })
    });
    showResult(slot, result);
  } catch (error) {
    showError(slot, error.message);
  } finally {
    setBusy(form, false);
  }
});

$("#apk-input")?.addEventListener("change", event => {
  $("#apk-file-name").textContent = event.target.files[0]?.name || "Choose an APK file";
});
$("#apk-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const slot = $("#apk-result");
  setBusy(form, true, "Inspecting…");
  showProgress(slot, "Scanning APK archive, manifest, permissions, and signing metadata…");
  try {
    const body = new FormData();
    body.append("file", $("#apk-input").files[0]);
    showResult(slot, await requestJson("/api/scan/apk", { method: "POST", body }));
  } catch (error) {
    showError(slot, error.message);
  } finally {
    setBusy(form, false);
  }
});

$("#image-input")?.addEventListener("change", event => {
  $("#image-file-name").textContent = event.target.files[0]?.name || "Choose an image";
});
$("#image-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const slot = $("#image-result");
  setBusy(form, true, "Removing…");
  showProgress(slot, "Sending the image to remove.bg securely. This may take a moment…");
  try {
    const body = new FormData();
    body.append("file", $("#image-input").files[0]);
    body.append("consent", $("#image-consent").checked ? "true" : "false");
    const response = await fetch("/api/scan/image", { method: "POST", body });
    if (!response.ok) {
      const type = response.headers.get("content-type") || "";
      const error = type.includes("application/json") ? await response.json() : {};
      throw new Error(error.error || `Background removal failed (${response.status}).`);
    }
    const blob = await response.blob();
    if (blob.type !== "image/png") {
      throw new Error("The server returned an unexpected file instead of a PNG.");
    }
    const disposition = response.headers.get("content-disposition") || "";
    const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "image-no-background.png";
    if (processedImageUrl) URL.revokeObjectURL(processedImageUrl);
    processedImageUrl = URL.createObjectURL(blob);
    const preview = el("figure", "processed-preview");
    const image = el("img", "", "");
    image.src = processedImageUrl;
    image.alt = "Background-removed transparent PNG";
    image.addEventListener("error", () => showError(slot, "The processed PNG could not be displayed."));
    preview.append(image, el("figcaption", "", "Processed result · transparent PNG"));
    const actions = el("div", "result-actions");
    const download = el("button", "button button-primary", "Download PNG");
    download.type = "button";
    download.addEventListener("click", () => {
      const link = document.createElement("a");
      link.href = processedImageUrl;
      link.download = filename;
      link.click();
    });
    actions.append(download);
    slot.replaceChildren(preview, actions);
  } catch (error) {
    const message = error instanceof TypeError
      ? "Could not reach the local analyzer. Check that the app is running and try again."
      : error.message;
    showError(slot, message);
  } finally {
    setBusy(form, false);
  }
});

window.addEventListener("beforeunload", () => {
  if (processedImageUrl) URL.revokeObjectURL(processedImageUrl);
});

async function downloadReport(id) {
  try {
    const response = await fetch(`/api/scans/${id}/report`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Request failed (${response.status}).`);
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `security-scan-${id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) {
    notify(error.message, true);
  }
}
