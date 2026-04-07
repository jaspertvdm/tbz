import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";

// ── Types ───────────────────────────────────────────────────────

interface Manifest {
  protocol: string;
  version: string;
  agent: string | null;
  title: string | null;
  created_at: string;
  created_by: string;
  hashes: Record<string, string>;
  stats: {
    total_files: number;
    total_bytes: number;
  };
  bundle_hash: string;
}

interface VerifyResult {
  valid: boolean;
  manifest: Manifest | null;
  verified_files: number;
  failed_files: string[];
  missing_files: string[];
}

interface ExtractResult {
  valid: boolean;
  forced: boolean;
  manifest: Manifest | null;
  extracted_files: string[];
  output_dir: string;
  verified_files: number;
}

type CardStatus = "pending" | "sealed" | "verified" | "corrupt" | "extracted";

interface TzaCard {
  id: string;
  path: string;
  filename: string;
  manifest: Manifest | null;
  status: CardStatus;
}

interface PendingFile {
  path: string;
  name: string;
  size: number;
}

// ── State ───────────────────────────────────────────────────────

let tzaCards: TzaCard[] = [];
let pendingFiles: PendingFile[] = [];

// ── DOM ─────────────────────────────────────────────────────────

let dropzone: HTMLElement;
let cardsEl: HTMLElement;
let actionsEl: HTMLElement;
let btnPack: HTMLButtonElement;
let btnClear: HTMLButtonElement;

// ── Init ────────────────────────────────────────────────────────

window.addEventListener("DOMContentLoaded", async () => {
  dropzone = document.getElementById("dropzone")!;
  cardsEl = document.getElementById("cards")!;
  actionsEl = document.getElementById("actions")!;
  btnPack = document.getElementById("btn-pack") as HTMLButtonElement;
  btnClear = document.getElementById("btn-clear") as HTMLButtonElement;

  setupDragDrop();
  setupButtons();
  await listenCliFile();
});

// ── Drag & Drop ─────────────────────────────────────────────────

function setupDragDrop() {
  // Click to open file picker
  dropzone.addEventListener("click", async () => {
    const selected = await open({
      multiple: true,
      directory: false,
      title: "Select files to bundle or .tza to verify",
      filters: [
        { name: "All Files", extensions: ["*"] },
        { name: "TBZ Archives", extensions: ["tza"] },
      ],
    });
    if (selected) {
      const paths = Array.isArray(selected) ? selected : [selected];
      handleDroppedPaths(paths);
    }
  });

  // Drag events (Tauri handles native file drop via events)
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag-over");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("drag-over");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag-over");
    // For Tauri native drop, we listen to tauri events
  });

  // Tauri file drop event
  listen<{ paths: string[] }>("tauri://drag-drop", (event) => {
    if (event.payload.paths && event.payload.paths.length > 0) {
      handleDroppedPaths(event.payload.paths);
    }
  });
}

// ── Handle dropped paths ────────────────────────────────────────

async function handleDroppedPaths(paths: string[]) {
  for (const path of paths) {
    if (path.endsWith(".tza") || path.endsWith(".tibet.zip")) {
      await verifyAndShowCard(path);
    } else {
      // Add to pending files for packing
      const name = path.split(/[/\\]/).pop() || path;
      pendingFiles.push({ path, name, size: 0 });
    }
  }
  render();
}

// ── Verify .tza ─────────────────────────────────────────────────

async function verifyAndShowCard(tzaPath: string) {
  showProgress("Verifying...");

  try {
    const result: VerifyResult = await invoke("verify_tza", { tzaPath });
    const filename = tzaPath.split(/[/\\]/).pop() || tzaPath;

    const card: TzaCard = {
      id: crypto.randomUUID(),
      path: tzaPath,
      filename,
      manifest: result.manifest,
      status: result.valid ? "verified" : "corrupt",
    };
    tzaCards.push(card);
  } catch (e) {
    const filename = tzaPath.split(/[/\\]/).pop() || tzaPath;
    const card: TzaCard = {
      id: crypto.randomUUID(),
      path: tzaPath,
      filename,
      manifest: null,
      status: "corrupt",
    };
    tzaCards.push(card);
  }

  hideProgress();
  render();
}

// ── Pack .tza ───────────────────────────────────────────────────

async function packFiles() {
  if (pendingFiles.length === 0) return;

  const outputPath = await save({
    title: "Save .tza bundle",
    defaultPath: "bundle.tza",
    filters: [{ name: "TBZ Archive", extensions: ["tza"] }],
  });

  if (!outputPath) return;

  showProgress("Packing...");

  try {
    // Use the first file's path. If single file, pack that file.
    // If multiple, we need a directory — for now pack first item
    const sourcePath = pendingFiles[0].path;

    const manifest: Manifest = await invoke("create_tza", {
      sourcePath,
      outputPath,
      sender: null as string | null,
    });

    // Clear pending, add result card
    pendingFiles = [];
    const filename = outputPath.split(/[/\\]/).pop() || outputPath;

    tzaCards.push({
      id: crypto.randomUUID(),
      path: outputPath,
      filename,
      manifest,
      status: "sealed",
    });
  } catch (e) {
    alert(`Pack failed: ${e}`);
  }

  hideProgress();
  render();
}

// ── Extract .tza ────────────────────────────────────────────────

async function extractCard(cardId: string) {
  const card = tzaCards.find((c) => c.id === cardId);
  if (!card) return;

  const outputDir = await open({
    directory: true,
    title: "Select extraction folder",
  });

  if (!outputDir) return;

  showProgress("Extracting...");

  try {
    await invoke<ExtractResult>("extract_tza", {
      tzaPath: card.path,
      outputDir,
    });

    card.status = "extracted";
  } catch (e) {
    alert(`Extract failed: ${e}`);
  }

  hideProgress();
  render();
}

// ── Buttons ─────────────────────────────────────────────────────

function setupButtons() {
  btnPack.addEventListener("click", () => packFiles());
  btnClear.addEventListener("click", () => {
    pendingFiles = [];
    tzaCards = [];
    render();
  });
}

// ── CLI file event ──────────────────────────────────────────────

async function listenCliFile() {
  await listen<{ path: string; mode: string }>("cli-file", async (event) => {
    const { path, mode } = event.payload;
    if (mode === "verify" || path.endsWith(".tza")) {
      await verifyAndShowCard(path);
    } else if (mode === "pack") {
      pendingFiles.push({
        path,
        name: path.split(/[/\\]/).pop() || path,
        size: 0,
      });
      render();
    }
  });
}

// ── Render ──────────────────────────────────────────────────────

function render() {
  const hasPending = pendingFiles.length > 0;
  const hasCards = tzaCards.length > 0;

  // Toggle dropzone
  if (hasPending || hasCards) {
    dropzone.classList.add("hidden");
  } else {
    dropzone.classList.remove("hidden");
  }

  // Toggle action bar
  if (hasPending) {
    actionsEl.classList.add("visible");
  } else {
    actionsEl.classList.remove("visible");
  }

  // Render cards
  cardsEl.innerHTML = "";

  // Pending files
  for (const file of pendingFiles) {
    const el = document.createElement("div");
    el.className = "pending-card";
    el.innerHTML = `
      <span class="file-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="16" height="16"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg></span>
      <span class="file-name">${escapeHtml(file.name)}</span>
      <span class="file-size">${file.size ? formatBytes(file.size) : ""}</span>
      <button class="remove-btn" data-path="${escapeHtml(file.path)}">✕</button>
    `;
    el.querySelector(".remove-btn")!.addEventListener("click", (e) => {
      const path = (e.target as HTMLElement).getAttribute("data-path");
      pendingFiles = pendingFiles.filter((f) => f.path !== path);
      render();
    });
    cardsEl.appendChild(el);
  }

  // TZA cards
  for (const card of tzaCards) {
    const el = document.createElement("div");
    el.className = `file-card ${card.status}`;

    const statusIcon = getStatusIcon(card.status);
    const statusText = getStatusText(card.status);
    const statusClass = card.status === "corrupt" ? "fail" : card.status === "extracted" ? "neutral" : "ok";

    const agent = card.manifest?.agent || "—";
    const files = card.manifest?.stats.total_files ?? "?";
    const bytes = card.manifest?.stats.total_bytes
      ? formatBytes(card.manifest.stats.total_bytes)
      : "?";
    const date = card.manifest?.created_at
      ? formatDate(card.manifest.created_at)
      : "—";

    let actionsHtml = "";
    if (card.status === "verified" || card.status === "sealed") {
      actionsHtml = `<div class="card-actions">
        <button class="btn btn-ghost btn-small extract-btn" data-id="${card.id}">Extract</button>
      </div>`;
    }

    el.innerHTML = `
      <div class="card-status">${statusIcon}</div>
      <div class="card-info">
        <div class="card-filename">${escapeHtml(card.filename)}</div>
        <div class="card-meta">
          <span>Sender: ${escapeHtml(agent)}</span>
          <span>${files} files · ${bytes}</span>
          <span>${escapeHtml(date)}</span>
        </div>
        <div class="card-status-line ${statusClass}">
          ${statusIcon} ${statusText}
        </div>
        ${actionsHtml}
      </div>
    `;

    const extractBtn = el.querySelector(".extract-btn");
    if (extractBtn) {
      extractBtn.addEventListener("click", () => extractCard(card.id));
    }

    cardsEl.appendChild(el);
  }
}

// ── Progress overlay ────────────────────────────────────────────

function showProgress(text: string) {
  let overlay = document.querySelector(".progress-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "progress-overlay";
    document.body.appendChild(overlay);
  }
  overlay.innerHTML = `
    <div class="progress-box">
      <div class="spinner"></div>
      <div class="progress-text">${escapeHtml(text)}</div>
    </div>
  `;
}

function hideProgress() {
  const overlay = document.querySelector(".progress-overlay");
  if (overlay) overlay.remove();
}

// ── Helpers ─────────────────────────────────────────────────────

function getStatusIcon(status: CardStatus): string {
  const ok = `<svg class="status-svg ok" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  const fail = `<svg class="status-svg fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6" stroke-linecap="round"/></svg>`;
  const folder = `<svg class="status-svg neutral" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>`;
  const clock = `<svg class="status-svg neutral" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2" stroke-linecap="round"/></svg>`;
  switch (status) {
    case "sealed": return ok;
    case "verified": return ok;
    case "corrupt": return fail;
    case "extracted": return folder;
    case "pending": return clock;
  }
}

function getStatusText(status: CardStatus): string {
  switch (status) {
    case "sealed": return "Sealed — integrity verified";
    case "verified": return "Verified — all files intact";
    case "corrupt": return "CORRUPT — integrity check failed";
    case "extracted": return "Extracted";
    case "pending": return "Pending";
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString("nl-NL", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
