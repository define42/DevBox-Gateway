// Source for the dashboard UI. Run "tsc -p tsconfig.json" to update static/dashboard.js.

const DEFAULT_VM_ERROR = "Unable to load virtual machines right now.";
const SESSION_CHECK_ERROR = "Unable to verify your session. Reload and sign in again.";
const CREATION_STATUS_UNKNOWN_ERROR = "The progress connection was interrupted. The DevBox may still be being created; check the dashboard before trying again.";
const RTT_PING_INTERVAL_MS = 2000;
const RTT_RECONNECT_DELAY_MS = 2000;
const RTT_GREEN_MAX_MS = 30;
const RTT_YELLOW_MAX_MS = 50;
const JITTER_GREEN_MAX_MS = 20;
const JITTER_YELLOW_MAX_MS = 50;
const SERVER_USAGE_YELLOW_MIN_PERCENT = 60;
const SERVER_USAGE_RED_ABOVE_PERCENT = 80;
const LOGIN_PATH = "/login";
const ADMIN_PATH = "/api/admin";
const ADMIN_BASE_IMAGES_PATH = "/api/admin/base-images";
const ADMIN_BASE_IMAGES_DELETE_PATH = "/api/admin/base-images/delete";
const HTTP_STATUS_UNAUTHORIZED = 401;

// The dashboard and administrator inventory share this bundle. Keep the path
// check deliberately narrow so an unrelated route below /api/admin is not
// mistaken for the administrator page; accepting trailing slashes makes direct
// navigation and redirects behave consistently.
const adminView = window.location.pathname.replace(/\/+$/, "") === ADMIN_PATH;

type Disposable = {
    dispose(): void;
};

type XTermConstructorOptions = {
    convertEol?: boolean;
    cursorBlink?: boolean;
    fontFamily?: string;
    fontSize?: number;
    theme?: Record<string, string>;
};

type XTermFitAddon = {
    fit(): void;
};

type XTermTerminal = {
    clear(): void;
    dispose(): void;
    focus(): void;
    loadAddon(addon: XTermFitAddon): void;
    onData(listener: (data: string) => void): Disposable;
    open(parent: HTMLElement): void;
    write(data: string | Uint8Array): void;
};

declare const Terminal: {
    new(options?: XTermConstructorOptions): XTermTerminal;
};

declare const FitAddon: {
    FitAddon: new() => XTermFitAddon;
};

type DashboardVM = {
    name: string;
    displayName: string;
    owner?: string;
    user?: string;
    baseImage?: string;
    createdAt?: string;
    lastUsed?: string;
    rdpFilename?: string;
    ip: string;
    state: string;
    memoryMiB: number;
    vcpu: number;
    volumeGB: number;
    rdpReady: boolean;
};

type VMTableCapabilities = {
    connections: boolean;
    lifecycle: boolean;
};

type DashboardDataResponse = {
    filename?: string;
    username?: string;
    isAdmin?: boolean;
    vms?: DashboardVM[];
    autoShutdownHours?: number;
    baseImages?: string[];
    error?: string;
};

type ServerResourceUsage = {
    usedBytes: number;
    totalBytes: number;
};

type ServerCPUUsage = {
    usagePercent: number;
};

type ServerDiskIOUsage = {
    usagePercent: number;
    readBytesPerSecond: number;
    writeBytesPerSecond: number;
};

type DashboardSocketMessage = {
    type?: string;
    id?: number;
    data?: DashboardDataResponse;
    serverMemory?: ServerResourceUsage;
    serverDisk?: ServerResourceUsage;
    serverDiskIO?: ServerDiskIOUsage;
    serverCPU?: ServerCPUUsage;
    error?: string;
};

type DashboardActionResponse = {
    ok?: boolean;
    message?: string;
    error?: string;
};

type AdminBaseImagesResponse = {
    baseImages?: string[];
    maxUploadBytes?: number;
    availableStorageBytes?: number;
    error?: string;
};

type DashboardCreationStreamEvent = {
    type?: unknown;
    copiedBytes?: unknown;
    totalBytes?: unknown;
    ok?: unknown;
    message?: unknown;
    error?: unknown;
};

type DashboardTerminalState = {
    open: boolean;
    vmName: string;
    vmDisplayName: string;
    status: string;
    error: string;
};

type DashboardVNCState = {
    open: boolean;
    vmName: string;
    vmDisplayName: string;
    src: string;
};

type DashboardCreateState = {
    open: boolean;
    error: string;
    active: boolean;
    phase: "idle" | "preparing" | "copying" | "finalizing";
    percent: number;
};

type DashboardInfoState = {
    open: boolean;
    vmName: string;
    vmDisplayName: string;
    ip: string;
    user: string;
    baseImage: string;
    created: string;
    lastUsed: string;
    vmState: string;
};

type DashboardBaseImageManagerState = {
    open: boolean;
    images: string[];
    maxUploadBytes: number;
    availableStorageBytes: number | null;
    loading: boolean;
    busy: boolean;
    phase: "idle" | "uploading" | "finalizing";
    percent: number | null;
    deleting: string;
    error: string;
    message: string;
};

type DashboardState = {
    vms: DashboardVM[];
    filename: string;
    isAdmin: boolean;
    autoShutdownHours: number;
    vmError: string;
    actionMessage: string;
    actionError: string;
    loading: boolean;
    busy: boolean;
    terminal: DashboardTerminalState;
    vnc: DashboardVNCState;
    create: DashboardCreateState;
    info: DashboardInfoState;
    baseImageManager: DashboardBaseImageManagerState;
};

type RequestResult<T> = {
    ok: boolean;
    data?: T;
    error?: string;
};

const state: DashboardState = {
    vms: [],
    filename: "rdpgw.rdp",
    isAdmin: false,
    autoShutdownHours: 0,
    vmError: "",
    actionMessage: "",
    actionError: "",
    loading: true,
    busy: false,
    terminal: {
        open: false,
        vmName: "",
        vmDisplayName: "",
        status: "",
        error: "",
    },
    vnc: {
        open: false,
        vmName: "",
        vmDisplayName: "",
        src: "",
    },
    create: {
        open: false,
        error: "",
        active: false,
        phase: "idle",
        percent: 0,
    },
    info: {
        open: false,
        vmName: "",
        vmDisplayName: "",
        ip: "",
        user: "",
        baseImage: "",
        created: "",
        lastUsed: "",
        vmState: "",
    },
    baseImageManager: {
        open: false,
        images: [],
        maxUploadBytes: 0,
        availableStorageBytes: null,
        loading: false,
        busy: false,
        phase: "idle",
        percent: null,
        deleting: "",
        error: "",
        message: "",
    },
};

let loadInFlight = false;
let dashboardInitialLoadComplete = false;

function isActiveState(vmState: string): boolean {
    const normalized = vmState.trim().toLowerCase();
    return normalized === "running" || normalized === "paused" || normalized === "suspended";
}

function formatMemoryGB(memoryMiB?: number | string | null): string {
    if (!memoryMiB) {
        return "n/a";
    }
    const gb = Number(memoryMiB) / 1024;
    const formatted = Number.isInteger(gb) ? gb.toFixed(0) : gb.toFixed(1);
    return `${formatted} GB`;
}

function formatBytes(bytes?: number | null): string {
    if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes <= 0) {
        return "";
    }
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    const digits = value >= 10 || unit === 0 ? 0 : 1;
    return `${value.toFixed(digits)} ${units[unit]}`;
}

function formatBytesPerSecond(bytesPerSecond: number): string {
    return `${formatBytes(bytesPerSecond) || "0 B"}/s`;
}

function formatServerCapacityGB(bytes: number): string {
    const gib = bytes / (1024 ** 3);
    const rounded = Math.round(gib * 10) / 10;
    const formatted = Number.isInteger(rounded) ? rounded.toFixed(0) : rounded.toFixed(1);
    return `${formatted} GB`;
}

// formatCreatedAt turns the RFC3339 UTC timestamp stored on the VM into a
// human-readable local date/time. Unparseable or empty values fall back to a
// placeholder so older VMs without the metadata still render cleanly.
function formatCreatedAt(createdAt?: string): string {
    const raw = (createdAt || "").trim();
    if (raw === "") {
        return "n/a";
    }
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) {
        return raw;
    }
    return parsed.toLocaleString();
}

// formatDurationShort renders a millisecond span as a compact human duration
// ("3d 4h", "2h 15m", "45m"), rounding up to whole minutes so a countdown
// never shows more time gone than actually is.
function formatDurationShort(ms: number): string {
    const totalMinutes = Math.ceil(ms / 60000);
    const days = Math.floor(totalMinutes / 1440);
    const hours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = totalMinutes % 60;
    if (days > 0) {
        return `${days}d ${hours}h`;
    }
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    }
    return `${Math.max(minutes, 1)}m`;
}

// formatAutoShutdown renders when the idle reaper will stop the VM: the
// last-used time plus the configured VDI_AUTO_SHUTDOWN_HOURS limit. Only
// running VMs are candidates, so anything else shows n/a; "imminent" means the
// limit has already passed and the gateway is about to ask the guest to shut
// down (force-stop follows a few minutes later if it does not).
function formatAutoShutdown(lastUsed: string, vmState: string): string {
    if (state.autoShutdownHours <= 0) {
        return "Disabled";
    }
    if (vmState.trim().toLowerCase() !== "running") {
        return "n/a";
    }
    const raw = (lastUsed || "").trim();
    if (raw === "") {
        return "n/a";
    }
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) {
        return "n/a";
    }
    const remainingMs = parsed.getTime() + state.autoShutdownHours * 3600000 - Date.now();
    if (remainingMs <= 0) {
        return "imminent";
    }
    return `in ${formatDurationShort(remainingMs)}`;
}

function clampCreationPercent(value: number): number | null {
    if (!Number.isFinite(value)) {
        return null;
    }
    return Math.min(100, Math.max(0, value));
}

// setIconLabel renders a Bootstrap Icon followed by a text label inside a button
// (or anchor). Labels are static, but we build the nodes explicitly rather than
// using innerHTML to keep the rendering path free of HTML string injection.
function setIconLabel(el: HTMLElement, iconClass: string, label: string): void {
    el.textContent = "";
    const icon = document.createElement("i");
    icon.className = `bi ${iconClass} me-1`;
    icon.setAttribute("aria-hidden", "true");
    el.append(icon, label);
}

function terminalWebSocketURL(name: string): string {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}/api/dashboard/console/${encodeURIComponent(name)}/ws`;
}

function dashboardWebSocketURL(): string {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const path = adminView ? "/api/admin/ws" : "/api/dashboard/ws";
    return `${scheme}://${window.location.host}${path}`;
}

function dashboardDataURL(): string {
    return adminView ? "/api/admin/data" : "/api/dashboard/data";
}

function vncFrameURL(name: string): string {
    const params = new URLSearchParams({
        autoconnect: "1",
        path: `api/dashboard/vnc/${name}/ws`,
        reconnect: "1",
        reconnect_delay: "1500",
        resize: "remote",
        shared: "1",
        ts: `${Date.now()}`,
    });
    return `/static/novnc/vnc.html?${params.toString()}`;
}

function bootstrap(): void {
    const root = document.getElementById("app");
    if (!root) {
        return;
    }

    root.innerHTML = `
    <main class="container py-4">
      <div class="card shadow-sm">
        <div class="card-body">
          <div class="dashboard-header ${adminView ? "dashboard-header--admin" : ""} mb-4">
            <div class="dashboard-heading">
              <h1 class="h4 mb-1" id="page-title">Available DevBoxes</h1>
              <p class="text-body-secondary mb-0" id="page-subtitle">Live inventory.</p>
            </div>
            <div class="dashboard-metrics" role="group" aria-label="Gateway health metrics">
              <span id="rtt-indicator" class="badge rounded-pill text-bg-secondary rtt-indicator" title="Live round-trip time to the gateway" aria-live="polite"><i class="bi bi-activity me-1" aria-hidden="true"></i>RTT: &ndash;&ndash;</span>
              <span id="jitter-indicator" class="badge rounded-pill text-bg-secondary jitter-indicator" title="Live RTT jitter (variation between samples)" aria-live="polite"><i class="bi bi-graph-up me-1" aria-hidden="true"></i>Jitter: &ndash;&ndash;</span>
              <span id="server-memory-indicator" class="badge rounded-pill text-bg-secondary server-memory-indicator" title="Current server memory usage" aria-live="polite" hidden><i class="bi bi-memory me-1" aria-hidden="true"></i>Memory: &ndash;&ndash;</span>
              <span id="server-disk-indicator" class="badge rounded-pill text-bg-secondary server-disk-indicator" title="Current usage of the filesystem backing VM storage" aria-live="polite" hidden><i class="bi bi-device-hdd me-1" aria-hidden="true"></i>Disk: &ndash;&ndash;</span>
              <span id="server-disk-io-indicator" class="badge rounded-pill text-bg-secondary server-disk-io-indicator" title="Current disk I/O utilization and throughput" aria-live="polite" hidden><i class="bi bi-arrow-down-up me-1" aria-hidden="true"></i>Disk I/O: &ndash;&ndash;</span>
              <span id="server-cpu-indicator" class="badge rounded-pill text-bg-secondary server-cpu-indicator" title="CPU utilization averaged across all logical CPUs" aria-live="polite" hidden><i class="bi bi-cpu me-1" aria-hidden="true"></i>CPU: &ndash;&ndash;</span>
            </div>
            <div class="dashboard-actions d-flex flex-wrap align-items-center gap-2">
              <a class="btn btn-outline-primary btn-sm" id="admin-view-link" href="/api/admin" hidden><i class="bi bi-shield-lock me-1" aria-hidden="true"></i>Admin</a>
              <button class="btn btn-outline-primary btn-sm" id="base-images-button" type="button" hidden><i class="bi bi-device-hdd me-1" aria-hidden="true"></i>Base Images</button>
              <a class="btn btn-outline-secondary btn-sm" id="dashboard-view-link" href="/api/dashboard" hidden><i class="bi bi-display me-1" aria-hidden="true"></i>My DevBoxes</a>
              <button class="btn btn-primary" id="open-create-button" type="button"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i>Create DevBox</button>
              <form method="post" action="/logout" class="m-0">
                <button class="btn btn-outline-secondary btn-sm" type="submit"><i class="bi bi-box-arrow-right me-1" aria-hidden="true"></i>Logout</button>
              </form>
            </div>
          </div>
          <div id="action-area" class="mt-3" aria-live="polite"></div>
          <div id="vm-list" class="mt-3"></div>
        </div>
      </div>
    </main>
    <div id="terminal-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="terminal-backdrop"></div>
      <div id="terminal-dialog" class="terminal-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="terminal-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="terminal-title">Serial Terminal</h2>
              <p class="text-body-secondary mb-0" id="terminal-subtitle"></p>
            </div>
            <div class="d-flex flex-wrap gap-2">
              <button class="btn btn-outline-secondary btn-sm" id="terminal-fullscreen" type="button"><i class="bi bi-arrows-fullscreen me-1" aria-hidden="true"></i>Fullscreen</button>
              <button class="btn btn-outline-secondary btn-sm" id="terminal-close" type="button"><i class="bi bi-x-lg me-1" aria-hidden="true"></i>Close</button>
            </div>
          </div>
          <div class="terminal-hint mb-2" id="terminal-status" aria-live="polite"></div>
          <div class="alert alert-danger mb-3 d-none" id="terminal-error" role="alert"></div>
          <div class="terminal-modal__surface" id="terminal-surface"></div>
        </div>
      </div>
    </div>
    <div id="vnc-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="vnc-backdrop"></div>
      <div id="vnc-dialog" class="terminal-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="vnc-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="vnc-title">NoVNC</h2>
              <p class="text-body-secondary mb-0" id="vnc-subtitle"></p>
            </div>
            <button class="btn btn-outline-secondary btn-sm" id="vnc-close" type="button"><i class="bi bi-x-lg me-1" aria-hidden="true"></i>Close</button>
          </div>
          <div class="terminal-hint mb-2">Browser display via the VM's QEMU VNC socket. Drag the lower-right corner to resize, and use noVNC's own fullscreen control inside the viewer.</div>
          <div class="terminal-modal__surface terminal-modal__surface--iframe">
            <iframe id="vnc-frame" class="vnc-modal__frame" title="NoVNC session" loading="lazy" allowfullscreen></iframe>
          </div>
        </div>
      </div>
    </div>
    <div id="info-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="info-backdrop"></div>
      <div class="terminal-modal__dialog terminal-modal__dialog--form" role="dialog" aria-modal="true" aria-labelledby="info-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="info-title">DevBox Info</h2>
              <p class="text-body-secondary mb-0" id="info-subtitle"></p>
            </div>
            <button class="btn btn-outline-secondary btn-sm" id="info-close" type="button"><i class="bi bi-x-lg me-1" aria-hidden="true"></i>Close</button>
          </div>
          <dl class="row mb-0">
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">IP Address</dt>
            <dd class="col-8 col-sm-9 mb-2" id="info-ip"></dd>
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">User</dt>
            <dd class="col-8 col-sm-9 mb-2" id="info-user"></dd>
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">Image</dt>
            <dd class="col-8 col-sm-9 mb-2 text-break" id="info-image"></dd>
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">Created</dt>
            <dd class="col-8 col-sm-9 mb-2" id="info-created"></dd>
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">Last used</dt>
            <dd class="col-8 col-sm-9 mb-2" id="info-last-used"></dd>
            <dt class="col-4 col-sm-3 text-body-secondary fw-normal">Auto-shutdown</dt>
            <dd class="col-8 col-sm-9 mb-0" id="info-auto-shutdown"></dd>
          </dl>
        </div>
      </div>
    </div>
    <div id="base-images-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="base-images-backdrop"></div>
      <div class="terminal-modal__dialog terminal-modal__dialog--form" role="dialog" aria-modal="true" aria-labelledby="base-images-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="base-images-title">Base Images</h2>
              <p class="text-body-secondary mb-0">Manage the disk images available when a DevBox is created.</p>
            </div>
            <button class="btn btn-outline-secondary btn-sm" id="base-images-close" type="button"><i class="bi bi-x-lg me-1" aria-hidden="true"></i>Close</button>
          </div>
          <div class="alert alert-danger mb-3 d-none" id="base-images-error" role="alert"></div>
          <div class="alert alert-success mb-3 d-none" id="base-images-message" role="status"></div>
          <div class="alert alert-secondary d-flex flex-wrap align-items-center justify-content-between gap-2 py-2 mb-3" role="status">
            <span><i class="bi bi-device-hdd me-2" aria-hidden="true"></i>Available storage in base-image folder</span>
            <strong id="base-image-available-storage" aria-live="polite">Loading...</strong>
          </div>
          <form class="row g-3 align-items-end mb-4" id="base-image-upload-form">
            <div class="col-12 col-md-8">
              <label class="form-label" for="base-image-file">Upload Base Image</label>
              <input class="form-control" id="base-image-file" name="base_image" type="file" accept=".img,.qcow2,.raw" required>
              <div class="form-text" id="base-image-upload-limit">QCOW2 content required; filenames may end in .img, .qcow2, or .raw.</div>
            </div>
            <div class="col-12 col-md-4 d-grid">
              <button class="btn btn-primary" id="base-image-upload-button" type="submit"><i class="bi bi-upload me-1" aria-hidden="true"></i>Upload</button>
            </div>
          </form>
          <div class="mb-4 d-none" id="base-image-upload-progress">
            <div class="d-flex align-items-center justify-content-between gap-3 mb-2">
              <span class="d-inline-flex align-items-center gap-2">
                <span class="spinner-border spinner-border-sm" id="base-image-upload-spinner" aria-hidden="true"></span>
                <span id="base-image-upload-label" role="status" aria-live="polite" aria-atomic="true">Uploading base image...</span>
              </span>
              <span class="text-body-secondary" id="base-image-upload-value" aria-hidden="true"></span>
            </div>
            <div class="progress d-none" id="base-image-upload-track">
              <div class="progress-bar progress-bar-striped progress-bar-animated" id="base-image-upload-bar" role="progressbar" aria-labelledby="base-image-upload-label" aria-valuemin="0" aria-valuemax="100" aria-valuetext="Uploading base image" style="width: 0%"></div>
            </div>
          </div>
          <h3 class="h6">Available Images</h3>
          <div id="base-images-list" aria-live="polite"></div>
        </div>
      </div>
    </div>
    <div id="create-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="create-backdrop"></div>
      <div class="terminal-modal__dialog terminal-modal__dialog--form" role="dialog" aria-modal="true" aria-labelledby="create-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="create-title">Create DevBox</h2>
              <p class="text-body-secondary mb-0">Provision a new virtual machine.</p>
            </div>
            <button class="btn btn-outline-secondary btn-sm" id="create-close" type="button"><i class="bi bi-x-lg me-1" aria-hidden="true"></i>Close</button>
          </div>
          <div class="alert alert-danger mb-3 d-none" id="create-error" role="alert"></div>
          <div class="mb-3 d-none" id="create-progress">
            <div class="d-flex align-items-center justify-content-between gap-3 mb-2">
              <span class="d-inline-flex align-items-center gap-2">
                <span class="spinner-border spinner-border-sm" id="create-progress-spinner" aria-hidden="true"></span>
                <span id="create-progress-label" role="status" aria-live="polite" aria-atomic="true">Preparing DevBox...</span>
              </span>
              <span class="text-body-secondary" id="create-progress-value" aria-hidden="true"></span>
            </div>
            <div class="progress d-none" id="create-progress-track">
              <div class="progress-bar progress-bar-striped progress-bar-animated" id="create-progress-bar" role="progressbar" aria-labelledby="create-progress-label" aria-valuemin="0" aria-valuemax="100" aria-valuetext="Preparing DevBox..." style="width: 0%"></div>
            </div>
          </div>
          <form class="row g-3 align-items-end" id="create-form">
            <div class="col-12 col-md-6 col-lg-4">
              <label class="form-label" for="vm-name">New DevBox Name</label>
              <input class="form-control" id="vm-name" name="vm_name" autocomplete="off" pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" maxlength="63" title="Lowercase letters, numbers, and hyphens only. Must start/end with a letter or number. Max 63 characters." autocapitalize="none" spellcheck="false" required>
            </div>
            <div class="col-12 col-md-6 col-lg-4">
              <label class="form-label" for="vm-base-image">Base Image</label>
              <select class="form-select" id="vm-base-image" name="vm_base_image" title="Disk image cloned for the new DevBox." required>
                <option value="" disabled selected>Loading base images...</option>
              </select>
            </div>
            <div class="col-12 col-md-6 col-lg-4">
              <label class="form-label" for="vm-username">Username</label>
              <input class="form-control" id="vm-username" name="vm_username" autocomplete="off" pattern="[a-z_][a-z0-9_\\-]*" maxlength="32" title="Login user created inside the DevBox. Lowercase letters, numbers, hyphens, or underscores. Must start with a letter or underscore. Max 32 characters." autocapitalize="none" spellcheck="false">
            </div>
            <div class="col-12">
              <p class="form-text mb-0">The DevBox account is created with the password you used to sign in to this gateway.</p>
            </div>
            <div class="col-12 col-md-6 col-lg-4 d-grid align-self-end">
              <button class="btn btn-primary" id="create-button" type="submit"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i>Create DevBox</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  `;

    const pageTitle = root.querySelector<HTMLHeadingElement>("#page-title");
    const pageSubtitle = root.querySelector<HTMLParagraphElement>("#page-subtitle");
    const adminViewLink = root.querySelector<HTMLAnchorElement>("#admin-view-link");
    const dashboardViewLink = root.querySelector<HTMLAnchorElement>("#dashboard-view-link");
    const baseImagesButton = root.querySelector<HTMLButtonElement>("#base-images-button");
    const form = root.querySelector<HTMLFormElement>("#create-form");
    const input = root.querySelector<HTMLInputElement>("#vm-name");
    const usernameInput = root.querySelector<HTMLInputElement>("#vm-username");
    const baseImageSelect = root.querySelector<HTMLSelectElement>("#vm-base-image");
    const createButton = root.querySelector<HTMLButtonElement>("#create-button");
    const rttIndicator = root.querySelector<HTMLSpanElement>("#rtt-indicator");
    const jitterIndicator = root.querySelector<HTMLSpanElement>("#jitter-indicator");
    const serverMemoryIndicator = root.querySelector<HTMLSpanElement>("#server-memory-indicator");
    const serverDiskIndicator = root.querySelector<HTMLSpanElement>("#server-disk-indicator");
    const serverDiskIOIndicator = root.querySelector<HTMLSpanElement>("#server-disk-io-indicator");
    const serverCPUIndicator = root.querySelector<HTMLSpanElement>("#server-cpu-indicator");
    const actionArea = root.querySelector<HTMLDivElement>("#action-area");
    const listArea = root.querySelector<HTMLDivElement>("#vm-list");
    const terminalModal = root.querySelector<HTMLDivElement>("#terminal-modal");
    const terminalBackdrop = root.querySelector<HTMLDivElement>("#terminal-backdrop");
    const terminalDialog = root.querySelector<HTMLDivElement>("#terminal-dialog");
    const terminalSubtitle = root.querySelector<HTMLParagraphElement>("#terminal-subtitle");
    const terminalStatus = root.querySelector<HTMLDivElement>("#terminal-status");
    const terminalError = root.querySelector<HTMLDivElement>("#terminal-error");
    const terminalSurface = root.querySelector<HTMLDivElement>("#terminal-surface");
    const terminalFullscreen = root.querySelector<HTMLButtonElement>("#terminal-fullscreen");
    const terminalClose = root.querySelector<HTMLButtonElement>("#terminal-close");
    const vncModal = root.querySelector<HTMLDivElement>("#vnc-modal");
    const vncBackdrop = root.querySelector<HTMLDivElement>("#vnc-backdrop");
    const vncDialog = root.querySelector<HTMLDivElement>("#vnc-dialog");
    const vncSubtitle = root.querySelector<HTMLParagraphElement>("#vnc-subtitle");
    const vncFrame = root.querySelector<HTMLIFrameElement>("#vnc-frame");
    const vncClose = root.querySelector<HTMLButtonElement>("#vnc-close");
    const openCreateButton = root.querySelector<HTMLButtonElement>("#open-create-button");
    const createModal = root.querySelector<HTMLDivElement>("#create-modal");
    const createBackdrop = root.querySelector<HTMLDivElement>("#create-backdrop");
    const createClose = root.querySelector<HTMLButtonElement>("#create-close");
    const createError = root.querySelector<HTMLDivElement>("#create-error");
    const createProgress = root.querySelector<HTMLDivElement>("#create-progress");
    const createProgressSpinner = root.querySelector<HTMLSpanElement>("#create-progress-spinner");
    const createProgressLabel = root.querySelector<HTMLSpanElement>("#create-progress-label");
    const createProgressValue = root.querySelector<HTMLSpanElement>("#create-progress-value");
    const createProgressTrack = root.querySelector<HTMLDivElement>("#create-progress-track");
    const createProgressBar = root.querySelector<HTMLDivElement>("#create-progress-bar");
    const infoModal = root.querySelector<HTMLDivElement>("#info-modal");
    const infoBackdrop = root.querySelector<HTMLDivElement>("#info-backdrop");
    const infoSubtitle = root.querySelector<HTMLParagraphElement>("#info-subtitle");
    const infoIP = root.querySelector<HTMLElement>("#info-ip");
    const infoUser = root.querySelector<HTMLElement>("#info-user");
    const infoImage = root.querySelector<HTMLElement>("#info-image");
    const infoCreated = root.querySelector<HTMLElement>("#info-created");
    const infoLastUsed = root.querySelector<HTMLElement>("#info-last-used");
    const infoAutoShutdown = root.querySelector<HTMLElement>("#info-auto-shutdown");
    const infoClose = root.querySelector<HTMLButtonElement>("#info-close");
    const baseImagesModal = root.querySelector<HTMLDivElement>("#base-images-modal");
    const baseImagesBackdrop = root.querySelector<HTMLDivElement>("#base-images-backdrop");
    const baseImagesClose = root.querySelector<HTMLButtonElement>("#base-images-close");
    const baseImagesError = root.querySelector<HTMLDivElement>("#base-images-error");
    const baseImagesMessage = root.querySelector<HTMLDivElement>("#base-images-message");
    const baseImageUploadForm = root.querySelector<HTMLFormElement>("#base-image-upload-form");
    const baseImageFile = root.querySelector<HTMLInputElement>("#base-image-file");
    const baseImageUploadButton = root.querySelector<HTMLButtonElement>("#base-image-upload-button");
    const baseImageUploadLimit = root.querySelector<HTMLDivElement>("#base-image-upload-limit");
    const baseImageAvailableStorage = root.querySelector<HTMLElement>("#base-image-available-storage");
    const baseImageUploadProgress = root.querySelector<HTMLDivElement>("#base-image-upload-progress");
    const baseImageUploadSpinner = root.querySelector<HTMLSpanElement>("#base-image-upload-spinner");
    const baseImageUploadLabel = root.querySelector<HTMLSpanElement>("#base-image-upload-label");
    const baseImageUploadValue = root.querySelector<HTMLSpanElement>("#base-image-upload-value");
    const baseImageUploadTrack = root.querySelector<HTMLDivElement>("#base-image-upload-track");
    const baseImageUploadBar = root.querySelector<HTMLDivElement>("#base-image-upload-bar");
    const baseImagesList = root.querySelector<HTMLDivElement>("#base-images-list");

    if (
        !pageTitle ||
        !pageSubtitle ||
        !adminViewLink ||
        !dashboardViewLink ||
        !baseImagesButton ||
        !form ||
        !input ||
        !usernameInput ||
        !baseImageSelect ||
        !createButton ||
        !rttIndicator ||
        !jitterIndicator ||
        !serverMemoryIndicator ||
        !serverDiskIndicator ||
        !serverDiskIOIndicator ||
        !serverCPUIndicator ||
        !actionArea ||
        !listArea ||
        !terminalModal ||
        !terminalBackdrop ||
        !terminalDialog ||
        !terminalSubtitle ||
        !terminalStatus ||
        !terminalError ||
        !terminalSurface ||
        !terminalFullscreen ||
        !terminalClose ||
        !vncModal ||
        !vncBackdrop ||
        !vncDialog ||
        !vncSubtitle ||
        !vncFrame ||
        !vncClose ||
        !openCreateButton ||
        !createModal ||
        !createBackdrop ||
        !createClose ||
        !createError ||
        !createProgress ||
        !createProgressSpinner ||
        !createProgressLabel ||
        !createProgressValue ||
        !createProgressTrack ||
        !createProgressBar ||
        !infoModal ||
        !infoBackdrop ||
        !infoSubtitle ||
        !infoIP ||
        !infoUser ||
        !infoImage ||
        !infoCreated ||
        !infoLastUsed ||
        !infoAutoShutdown ||
        !infoClose ||
        !baseImagesModal ||
        !baseImagesBackdrop ||
        !baseImagesClose ||
        !baseImagesError ||
        !baseImagesMessage ||
        !baseImageUploadForm ||
        !baseImageFile ||
        !baseImageUploadButton ||
        !baseImageUploadLimit ||
        !baseImageAvailableStorage ||
        !baseImageUploadProgress ||
        !baseImageUploadSpinner ||
        !baseImageUploadLabel ||
        !baseImageUploadValue ||
        !baseImageUploadTrack ||
        !baseImageUploadBar ||
        !baseImagesList
    ) {
        return;
    }

    const pageTitleEl = pageTitle;
    const pageSubtitleEl = pageSubtitle;
    const adminViewLinkEl = adminViewLink;
    const dashboardViewLinkEl = dashboardViewLink;
    const baseImagesButtonEl = baseImagesButton;
    const formEl = form;
    const inputEl = input;
    const usernameInputEl = usernameInput;
    const baseImageSelectEl = baseImageSelect;
    const createButtonEl = createButton;
    const rttIndicatorEl = rttIndicator;
    const jitterIndicatorEl = jitterIndicator;
    const serverMemoryIndicatorEl = serverMemoryIndicator;
    const serverDiskIndicatorEl = serverDiskIndicator;
    const serverDiskIOIndicatorEl = serverDiskIOIndicator;
    const serverCPUIndicatorEl = serverCPUIndicator;
    const actionAreaEl = actionArea;
    const listAreaEl = listArea;
    const terminalModalEl = terminalModal;
    const terminalBackdropEl = terminalBackdrop;
    const terminalDialogEl = terminalDialog;
    const terminalSubtitleEl = terminalSubtitle;
    const terminalStatusEl = terminalStatus;
    const terminalErrorEl = terminalError;
    const terminalSurfaceEl = terminalSurface;
    const terminalFullscreenEl = terminalFullscreen;
    const terminalCloseEl = terminalClose;
    const vncModalEl = vncModal;
    const vncBackdropEl = vncBackdrop;
    const vncDialogEl = vncDialog;
    const vncSubtitleEl = vncSubtitle;
    const vncFrameEl = vncFrame;
    const vncCloseEl = vncClose;
    const openCreateButtonEl = openCreateButton;
    const createModalEl = createModal;
    const createBackdropEl = createBackdrop;
    const createCloseEl = createClose;
    const createErrorEl = createError;
    const createProgressEl = createProgress;
    const createProgressSpinnerEl = createProgressSpinner;
    const createProgressLabelEl = createProgressLabel;
    const createProgressValueEl = createProgressValue;
    const createProgressTrackEl = createProgressTrack;
    const createProgressBarEl = createProgressBar;
    const infoModalEl = infoModal;
    const infoBackdropEl = infoBackdrop;
    const infoSubtitleEl = infoSubtitle;
    const infoIPEl = infoIP;
    const infoUserEl = infoUser;
    const infoImageEl = infoImage;
    const infoCreatedEl = infoCreated;
    const infoLastUsedEl = infoLastUsed;
    const infoAutoShutdownEl = infoAutoShutdown;
    const infoCloseEl = infoClose;
    const baseImagesModalEl = baseImagesModal;
    const baseImagesBackdropEl = baseImagesBackdrop;
    const baseImagesCloseEl = baseImagesClose;
    const baseImagesErrorEl = baseImagesError;
    const baseImagesMessageEl = baseImagesMessage;
    const baseImageUploadFormEl = baseImageUploadForm;
    const baseImageFileEl = baseImageFile;
    const baseImageUploadButtonEl = baseImageUploadButton;
    const baseImageUploadLimitEl = baseImageUploadLimit;
    const baseImageAvailableStorageEl = baseImageAvailableStorage;
    const baseImageUploadProgressEl = baseImageUploadProgress;
    const baseImageUploadSpinnerEl = baseImageUploadSpinner;
    const baseImageUploadLabelEl = baseImageUploadLabel;
    const baseImageUploadValueEl = baseImageUploadValue;
    const baseImageUploadTrackEl = baseImageUploadTrack;
    const baseImageUploadBarEl = baseImageUploadBar;
    const baseImagesListEl = baseImagesList;

    let terminalSocket: WebSocket | null = null;
    let terminalInstance: XTermTerminal | null = null;
    let terminalFitAddon: XTermFitAddon | null = null;
    let terminalInputDisposable: Disposable | null = null;
    let terminalClosing = false;
    let terminalResizeFrame = 0;
    let defaultUsername = "";
    let usernameInitialized = false;
    let baseImages: string[] = [];

    function renderPageMode(): void {
        if (adminView) {
            pageTitleEl.textContent = "All DevBoxes";
            pageSubtitleEl.textContent = "All VDIs on this system, grouped by user. Lifecycle controls apply system-wide.";
        }
        adminViewLinkEl.hidden = adminView || !state.isAdmin;
        dashboardViewLinkEl.hidden = !adminView;
        baseImagesButtonEl.hidden = !adminView;
        openCreateButtonEl.hidden = adminView;
        serverMemoryIndicatorEl.hidden = !adminView;
        serverDiskIndicatorEl.hidden = !adminView;
        serverDiskIOIndicatorEl.hidden = !adminView;
        serverCPUIndicatorEl.hidden = !adminView;
    }

    renderPageMode();

    const terminalResizeObserver = new ResizeObserver(() => {
        requestTerminalFit();
    });
    terminalResizeObserver.observe(terminalDialogEl);
    terminalResizeObserver.observe(terminalSurfaceEl);

    function isFullscreenTarget(element: HTMLElement): boolean {
        return document.fullscreenElement === element;
    }

    async function toggleFullscreen(element: HTMLElement): Promise<void> {
        try {
            if (isFullscreenTarget(element)) {
                await document.exitFullscreen();
                return;
            }
            await element.requestFullscreen();
        } catch (error) {
            console.error("fullscreen toggle failed", error);
        }
    }

    function exitFullscreenIfNeeded(element: HTMLElement): void {
        if (isFullscreenTarget(element)) {
            void document.exitFullscreen();
        }
    }

    function requestTerminalFit(): void {
        if (!state.terminal.open || !terminalFitAddon) {
            return;
        }
        if (terminalResizeFrame) {
            window.cancelAnimationFrame(terminalResizeFrame);
        }
        terminalResizeFrame = window.requestAnimationFrame(() => {
            terminalResizeFrame = 0;
            if (!state.terminal.open || !terminalFitAddon) {
                return;
            }
            try {
                terminalFitAddon.fit();
            } catch (error) {
                console.error("terminal fit failed", error);
            }
            if (terminalInstance) {
                terminalInstance.focus();
            }
        });
    }

    function renderServerUsagePercent(
        indicator: HTMLSpanElement,
        iconClass: string,
        label: string,
        usagePercent: number | null,
        details = "",
    ): void {
        indicator.classList.remove(
            "text-bg-success",
            "text-bg-warning",
            "text-bg-danger",
            "text-bg-secondary",
        );
        if (
            typeof usagePercent !== "number" ||
            !Number.isFinite(usagePercent) ||
            usagePercent < 0 ||
            usagePercent > 100
        ) {
            indicator.classList.add("text-bg-secondary");
            setIconLabel(indicator, iconClass, `${label}: --`);
            return;
        }

        const usedPercent = Math.round(usagePercent);
        let colorClass = "text-bg-success";
        if (usedPercent > SERVER_USAGE_RED_ABOVE_PERCENT) {
            colorClass = "text-bg-danger";
        } else if (usedPercent >= SERVER_USAGE_YELLOW_MIN_PERCENT) {
            colorClass = "text-bg-warning";
        }
        indicator.classList.add(colorClass);
        setIconLabel(indicator, iconClass, `${label}: ${usedPercent}%${details}`);
    }

    function renderServerUsage(
        indicator: HTMLSpanElement,
        iconClass: string,
        label: string,
        usage?: ServerResourceUsage | null,
    ): void {
        const usedBytes = usage?.usedBytes;
        const totalBytes = usage?.totalBytes;
        if (
            typeof usedBytes !== "number" ||
            !Number.isFinite(usedBytes) ||
            usedBytes < 0 ||
            typeof totalBytes !== "number" ||
            !Number.isFinite(totalBytes) ||
            totalBytes <= 0 ||
            usedBytes > totalBytes
        ) {
            renderServerUsagePercent(indicator, iconClass, label, null);
            return;
        }

        renderServerUsagePercent(
            indicator,
            iconClass,
            label,
            (usedBytes / totalBytes) * 100,
            ` · ${formatServerCapacityGB(usedBytes)} used / ${formatServerCapacityGB(totalBytes)} total`,
        );
    }

    function renderServerMemory(memory?: ServerResourceUsage | null): void {
        if (adminView) {
            renderServerUsage(serverMemoryIndicatorEl, "bi-memory", "Memory", memory);
        }
    }

    function renderServerDisk(disk?: ServerResourceUsage | null): void {
        if (adminView) {
            renderServerUsage(serverDiskIndicatorEl, "bi-device-hdd", "Disk", disk);
        }
    }

    function renderServerDiskIO(diskIO?: ServerDiskIOUsage | null): void {
        if (!adminView) {
            return;
        }
        const usagePercent = diskIO ? diskIO.usagePercent : null;
        const readBytesPerSecond = diskIO?.readBytesPerSecond;
        const writeBytesPerSecond = diskIO?.writeBytesPerSecond;
        if (
            typeof readBytesPerSecond !== "number" ||
            !Number.isFinite(readBytesPerSecond) ||
            readBytesPerSecond < 0 ||
            typeof writeBytesPerSecond !== "number" ||
            !Number.isFinite(writeBytesPerSecond) ||
            writeBytesPerSecond < 0
        ) {
            renderServerUsagePercent(serverDiskIOIndicatorEl, "bi-arrow-down-up", "Disk I/O", null);
            return;
        }
        renderServerUsagePercent(
            serverDiskIOIndicatorEl,
            "bi-arrow-down-up",
            "Disk I/O",
            usagePercent,
            ` · R ${formatBytesPerSecond(readBytesPerSecond)} · W ${formatBytesPerSecond(writeBytesPerSecond)}`,
        );
    }

    function renderServerCPU(cpu?: ServerCPUUsage | null): void {
        if (adminView) {
            const usagePercent = cpu ? cpu.usagePercent : null;
            renderServerUsagePercent(serverCPUIndicatorEl, "bi-cpu", "CPU", usagePercent);
        }
    }

    // renderRTT paints the live round-trip-time and jitter badges in the header.
    // The RTT colour follows the latency thresholds: green below 30ms, yellow from
    // 30 to 50ms, and red above 50ms. The jitter badge stays neutral. A null
    // reading means the last probe failed or the socket is down.
    function renderRTT(rttMs: number | null, jitterMs: number | null): void {
        rttIndicatorEl.classList.remove(
            "text-bg-success",
            "text-bg-warning",
            "text-bg-danger",
            "text-bg-secondary",
        );
        if (rttMs === null) {
            rttIndicatorEl.classList.add("text-bg-secondary");
            setIconLabel(rttIndicatorEl, "bi-activity", "RTT: --");
        } else {
            const rounded = Math.round(rttMs);
            let colorClass = "text-bg-success";
            if (rttMs > RTT_YELLOW_MAX_MS) {
                colorClass = "text-bg-danger";
            } else if (rttMs > RTT_GREEN_MAX_MS) {
                colorClass = "text-bg-warning";
            }
            rttIndicatorEl.classList.add(colorClass);
            setIconLabel(rttIndicatorEl, "bi-activity", `RTT: ${rounded} ms`);
        }

        jitterIndicatorEl.classList.remove(
            "text-bg-success",
            "text-bg-warning",
            "text-bg-danger",
            "text-bg-secondary",
        );
        if (jitterMs === null) {
            jitterIndicatorEl.classList.add("text-bg-secondary");
            setIconLabel(jitterIndicatorEl, "bi-graph-up", "Jitter: --");
        } else {
            let jitterClass = "text-bg-success";
            if (jitterMs > JITTER_YELLOW_MAX_MS) {
                jitterClass = "text-bg-danger";
            } else if (jitterMs > JITTER_GREEN_MAX_MS) {
                jitterClass = "text-bg-warning";
            }
            jitterIndicatorEl.classList.add(jitterClass);
            setIconLabel(jitterIndicatorEl, "bi-graph-up", `Jitter: ${Math.round(jitterMs)} ms`);
        }
    }

    let dashboardSocket: WebSocket | null = null;
    let rttPingHandle = 0;
    let dashboardReconnectHandle = 0;
    let dashboardSocketClosing = false;
    let dashboardSocketErrorChecked = false;
    let rttPrev: number | null = null;
    let rttJitter = 0;
    let rttHasJitter = false;

    function resetRTTStats(): void {
        rttPrev = null;
        rttJitter = 0;
        rttHasJitter = false;
    }

    // recordRTTSample folds a fresh round-trip reading into the smoothed jitter
    // estimate (RFC 3550-style mean deviation of successive samples) and repaints
    // both badges. Jitter needs two samples, so the first reading reports none.
    function recordRTTSample(rttMs: number): void {
        if (rttPrev !== null) {
            const diff = Math.abs(rttMs - rttPrev);
            rttJitter += (diff - rttJitter) / 16;
            rttHasJitter = true;
        }
        rttPrev = rttMs;
        renderRTT(rttMs, rttHasJitter ? rttJitter : null);
    }

    // sendRTTProbe stamps the current time into a typed ping message. The shared
    // dashboard socket returns a typed pong while also carrying VM updates.
    function sendRTTProbe(): void {
        if (!dashboardSocket || dashboardSocket.readyState !== WebSocket.OPEN) {
            return;
        }
        try {
            dashboardSocket.send(JSON.stringify({ type: "ping", id: performance.now() }));
        } catch {
            // A failed send means the socket is going away; onclose handles it.
        }
    }

    function stopRTTPing(): void {
        if (rttPingHandle) {
            window.clearInterval(rttPingHandle);
            rttPingHandle = 0;
        }
    }

    function scheduleDashboardReconnect(): void {
        if (dashboardSocketClosing || dashboardReconnectHandle) {
            return;
        }
        dashboardReconnectHandle = window.setTimeout(() => {
            dashboardReconnectHandle = 0;
            connectDashboardSocket();
        }, RTT_RECONNECT_DELAY_MS);
    }

    function applyDashboardData(data: DashboardDataResponse): void {
        state.vms = data.vms || [];
        // Preserve the last authenticated capability when a later WebSocket
        // snapshot omits the optional field. The normal dashboard starts with
        // the Admin link hidden and exposes it only after an explicit true.
        if (typeof data.isAdmin === "boolean") {
            state.isAdmin = data.isAdmin;
            renderPageMode();
        }
        // Serialized with omitempty, so an absent field means auto-shutdown is
        // disabled (0), not "keep the previous value".
        state.autoShutdownHours = typeof data.autoShutdownHours === "number" ? data.autoShutdownHours : 0;
        baseImages = data.baseImages || [];
        renderBaseImageOptions();
        refreshOpenInfo();
        if (data.filename) {
            state.filename = data.filename;
        }
        if (typeof data.username === "string" && data.username !== "") {
            defaultUsername = data.username;
            usernameInputEl.placeholder = defaultUsername;
            // Prefill the default once so a WebSocket recovery after a failed
            // HTTP bootstrap restores the logged-in user's guest username.
            if (!usernameInitialized && document.activeElement !== usernameInputEl) {
                usernameInputEl.value = defaultUsername;
                usernameInitialized = true;
            }
        }
        state.vmError = data.error || "";
    }

    function applyDashboardUpdate(message: DashboardSocketMessage): void {
        if (typeof message.error === "string" && message.error !== "") {
            state.vmError = message.error;
            renderVMList();
            return;
        }
        if (!message.data || !Array.isArray(message.data.vms)) {
            state.vmError = DEFAULT_VM_ERROR;
            renderVMList();
            return;
        }
        applyDashboardData(message.data);
        state.loading = false;
        renderVMList();
    }

    function handleDashboardSocketMessage(event: MessageEvent): void {
        if (typeof event.data !== "string") {
            return;
        }
        let message: DashboardSocketMessage;
        try {
            message = JSON.parse(event.data) as DashboardSocketMessage;
        } catch {
            return;
        }

        if (message.type === "pong" && typeof message.id === "number") {
            recordRTTSample(performance.now() - message.id);
            renderServerMemory(message.serverMemory);
            renderServerDisk(message.serverDisk);
            renderServerDiskIO(message.serverDiskIO);
            renderServerCPU(message.serverCPU);
            return;
        }
        if (message.type === "dashboard") {
            applyDashboardUpdate(message);
        }
    }

    // connectDashboardSocket keeps one authenticated connection open for both
    // RTT probes and cache-driven VM status pushes.
    function connectDashboardSocket(): void {
        if (dashboardSocketClosing || dashboardSocket) {
            return;
        }
        let socket: WebSocket;
        try {
            socket = new WebSocket(dashboardWebSocketURL());
        } catch {
            resetRTTStats();
            renderRTT(null, null);
            renderServerMemory(null);
            renderServerDisk(null);
            renderServerDiskIO(null);
            renderServerCPU(null);
            scheduleDashboardReconnect();
            return;
        }
        dashboardSocket = socket;

        socket.onopen = () => {
            if (dashboardSocket !== socket) {
                return;
            }
            dashboardSocketErrorChecked = false;
            sendRTTProbe();
            stopRTTPing();
            rttPingHandle = window.setInterval(() => {
                if (document.hidden) {
                    return;
                }
                sendRTTProbe();
            }, RTT_PING_INTERVAL_MS);
        };

        socket.onmessage = (event: MessageEvent) => {
            if (dashboardSocket !== socket) {
                return;
            }
            handleDashboardSocketMessage(event);
        };

        socket.onerror = () => {
            if (dashboardSocket === socket) {
                renderRTT(null, null);
                renderServerMemory(null);
                renderServerDisk(null);
                renderServerDiskIO(null);
                renderServerCPU(null);
                if (!dashboardSocketErrorChecked) {
                    dashboardSocketErrorChecked = true;
                    // WebSocket does not expose handshake status codes. This
                    // request redirects an expired session to the login page.
                    void requestJSON<DashboardDataResponse>(dashboardDataURL());
                }
            }
        };

        socket.onclose = () => {
            if (dashboardSocket === socket) {
                dashboardSocket = null;
            }
            stopRTTPing();
            // Drop the prior sample so a reconnect does not register a bogus
            // jitter spike across the gap.
            resetRTTStats();
            renderRTT(null, null);
            renderServerMemory(null);
            renderServerDisk(null);
            renderServerDiskIO(null);
            renderServerCPU(null);
            scheduleDashboardReconnect();
        };
    }

    function teardownDashboardSocket(): void {
        dashboardSocketClosing = true;
        stopRTTPing();
        if (dashboardReconnectHandle) {
            window.clearTimeout(dashboardReconnectHandle);
            dashboardReconnectHandle = 0;
        }
        if (dashboardSocket) {
            try {
                dashboardSocket.close();
            } catch {
                // Ignore close errors during teardown.
            }
            dashboardSocket = null;
        }
    }

    function renderAction(): void {
        actionAreaEl.innerHTML = "";
        if (state.actionError) {
            const error = document.createElement("div");
            error.className = "alert alert-danger mb-0";
            error.setAttribute("role", "alert");
            error.textContent = state.actionError;
            actionAreaEl.appendChild(error);
            return;
        }
        if (state.actionMessage) {
            const message = document.createElement("div");
            message.className = "btn btn-outline-success text-start w-100 disabled";
            message.textContent = state.actionMessage;
            actionAreaEl.appendChild(message);
        }
    }

    function renderTerminal(): void {
        terminalModalEl.hidden = !state.terminal.open;
        terminalModalEl.setAttribute("aria-hidden", state.terminal.open ? "false" : "true");
        terminalSubtitleEl.textContent = state.terminal.vmDisplayName || state.terminal.vmName;
        terminalStatusEl.textContent = state.terminal.status;
        if (isFullscreenTarget(terminalDialogEl)) {
            setIconLabel(terminalFullscreenEl, "bi-arrows-angle-contract", "Exit Fullscreen");
        } else {
            setIconLabel(terminalFullscreenEl, "bi-arrows-fullscreen", "Fullscreen");
        }
        if (state.terminal.error) {
            terminalErrorEl.textContent = state.terminal.error;
            terminalErrorEl.classList.remove("d-none");
        } else {
            terminalErrorEl.textContent = "";
            terminalErrorEl.classList.add("d-none");
        }
        if (!state.terminal.open) {
            terminalSurfaceEl.innerHTML = "";
        }
    }

    function renderVNC(): void {
        vncModalEl.hidden = !state.vnc.open;
        vncModalEl.setAttribute("aria-hidden", state.vnc.open ? "false" : "true");
        vncSubtitleEl.textContent = state.vnc.vmDisplayName || state.vnc.vmName;
        if (state.vnc.open) {
            if (vncFrameEl.getAttribute("src") !== state.vnc.src) {
                vncFrameEl.setAttribute("src", state.vnc.src);
            }
        } else {
            vncFrameEl.removeAttribute("src");
        }
    }

    function renderCreate(): void {
        createModalEl.hidden = !state.create.open;
        createModalEl.setAttribute("aria-hidden", state.create.open ? "false" : "true");
        formEl.setAttribute("aria-busy", state.create.active ? "true" : "false");
        createProgressEl.classList.toggle("d-none", !state.create.active);
        const isPreparing = state.create.active && state.create.phase === "preparing";
        createProgressSpinnerEl.classList.toggle("d-none", !isPreparing);
        createProgressTrackEl.classList.toggle("d-none", !state.create.active || isPreparing);
        if (state.create.active) {
            const isCopying = state.create.phase === "copying";
            createProgressBarEl.classList.toggle("progress-bar-animated", !isCopying);
            if (isCopying) {
                const percent = clampCreationPercent(state.create.percent) || 0;
                const roundedPercent = Math.round(percent);
                if (createProgressLabelEl.textContent !== "Creating qcow2 disk image...") {
                    createProgressLabelEl.textContent = "Creating qcow2 disk image...";
                }
                createProgressValueEl.textContent = `${roundedPercent}%`;
                createProgressBarEl.style.width = `${percent}%`;
                createProgressBarEl.setAttribute("aria-valuenow", `${percent}`);
                createProgressBarEl.removeAttribute("aria-valuetext");
            } else if (state.create.phase === "finalizing") {
                const progressMessage = "Disk image copied; finalizing DevBox...";
                if (createProgressLabelEl.textContent !== progressMessage) {
                    createProgressLabelEl.textContent = progressMessage;
                }
                createProgressValueEl.textContent = "100%";
                createProgressBarEl.style.width = "100%";
                createProgressBarEl.setAttribute("aria-valuenow", "100");
                createProgressBarEl.removeAttribute("aria-valuetext");
            } else {
                createProgressLabelEl.textContent = "Preparing DevBox...";
                createProgressValueEl.textContent = "";
                createProgressBarEl.style.width = "0%";
                createProgressBarEl.removeAttribute("aria-valuenow");
                createProgressBarEl.setAttribute("aria-valuetext", "Preparing DevBox...");
            }
        } else {
            createProgressBarEl.classList.add("progress-bar-animated");
            createProgressLabelEl.textContent = "Preparing DevBox...";
            createProgressValueEl.textContent = "";
            createProgressBarEl.style.width = "0%";
            createProgressBarEl.removeAttribute("aria-valuenow");
            createProgressBarEl.setAttribute("aria-valuetext", "Preparing DevBox...");
        }
        if (state.create.error) {
            createErrorEl.textContent = state.create.error;
            createErrorEl.classList.remove("d-none");
        } else {
            createErrorEl.textContent = "";
            createErrorEl.classList.add("d-none");
        }
    }

    function setCreateError(message: string): void {
        state.create.error = message;
        renderCreate();
        if (message && state.create.open) {
            createCloseEl.focus();
        }
    }

    function beginCreateProgress(): void {
        state.create.active = true;
        state.create.phase = "preparing";
        state.create.percent = 0;
        renderCreate();
        createCloseEl.focus();
    }

    function updateCreateDiskProgress(copiedBytes: number, totalBytes: number): void {
        if (
            !state.create.active ||
            !Number.isFinite(copiedBytes) ||
            !Number.isFinite(totalBytes) ||
            copiedBytes < 0 ||
            totalBytes <= 0
        ) {
            return;
        }
        const percent = clampCreationPercent(copiedBytes / totalBytes * 100);
        if (percent === null) {
            return;
        }
        state.create.percent = Math.max(state.create.percent, percent);
        state.create.phase = copiedBytes >= totalBytes ? "finalizing" : "copying";
        renderCreate();
    }

    function finishCreateProgress(): void {
        state.create.active = false;
        state.create.phase = "idle";
        state.create.percent = 0;
        renderCreate();
    }

    function openCreate(): void {
        closeTerminal();
        closeVNC();
        state.create.open = true;
        if (!state.create.active) {
            state.create.error = "";
        }
        renderCreate();
        (state.create.active ? createCloseEl : inputEl).focus();
    }

    function closeCreate(): void {
        const wasOpen = state.create.open;
        state.create.open = false;
        if (!state.create.active) {
            state.create.error = "";
        }
        renderCreate();
        if (wasOpen) {
            openCreateButtonEl.focus();
        }
    }

    function renderBaseImageManager(): void {
        const manager = state.baseImageManager;
        baseImagesModalEl.hidden = !manager.open;
        baseImagesModalEl.setAttribute("aria-hidden", manager.open ? "false" : "true");
        baseImageUploadFormEl.setAttribute("aria-busy", manager.busy ? "true" : "false");
        baseImageFileEl.disabled = manager.busy;
        baseImageUploadButtonEl.disabled = manager.busy;

        if (manager.loading) {
            baseImageAvailableStorageEl.textContent = "Loading...";
        } else if (manager.availableStorageBytes === null) {
            baseImageAvailableStorageEl.textContent = "Unavailable";
        } else if (manager.availableStorageBytes === 0) {
            baseImageAvailableStorageEl.textContent = "0 B";
        } else {
            baseImageAvailableStorageEl.textContent = formatBytes(manager.availableStorageBytes) || "Unavailable";
        }

        const limit = formatBytes(manager.maxUploadBytes);
        baseImageUploadLimitEl.textContent = limit
            ? `QCOW2 content required; filenames may end in .img, .qcow2, or .raw. Maximum file size: ${limit}.`
            : "QCOW2 content required; filenames may end in .img, .qcow2, or .raw.";

        if (manager.error) {
            baseImagesErrorEl.textContent = manager.error;
            baseImagesErrorEl.classList.remove("d-none");
        } else {
            baseImagesErrorEl.textContent = "";
            baseImagesErrorEl.classList.add("d-none");
        }
        if (manager.message) {
            baseImagesMessageEl.textContent = manager.message;
            baseImagesMessageEl.classList.remove("d-none");
        } else {
            baseImagesMessageEl.textContent = "";
            baseImagesMessageEl.classList.add("d-none");
        }

        const uploading = manager.busy && manager.deleting === "";
        baseImageUploadProgressEl.classList.toggle("d-none", !uploading);
        if (uploading) {
            const finalizing = manager.phase === "finalizing";
            const percent = finalizing ? 100 : manager.percent;
            baseImageUploadLabelEl.textContent = finalizing
                ? "Upload complete; adding image to the library..."
                : "Uploading base image...";
            baseImageUploadSpinnerEl.classList.toggle("d-none", percent !== null && !finalizing);
            baseImageUploadTrackEl.classList.toggle("d-none", percent === null);
            if (percent !== null) {
                const rounded = Math.max(0, Math.min(100, Math.round(percent)));
                baseImageUploadValueEl.textContent = `${rounded}%`;
                baseImageUploadBarEl.style.width = `${rounded}%`;
                baseImageUploadBarEl.setAttribute("aria-valuenow", `${rounded}`);
                baseImageUploadBarEl.removeAttribute("aria-valuetext");
            } else {
                baseImageUploadValueEl.textContent = "";
                baseImageUploadBarEl.style.width = "0%";
                baseImageUploadBarEl.removeAttribute("aria-valuenow");
                baseImageUploadBarEl.setAttribute("aria-valuetext", "Uploading base image");
            }
            setIconLabel(baseImageUploadButtonEl, "bi-upload", "Uploading...");
        } else {
            baseImageUploadSpinnerEl.classList.remove("d-none");
            baseImageUploadTrackEl.classList.add("d-none");
            baseImageUploadValueEl.textContent = "";
            baseImageUploadBarEl.style.width = "0%";
            baseImageUploadBarEl.removeAttribute("aria-valuenow");
            baseImageUploadBarEl.setAttribute("aria-valuetext", "Uploading base image");
            setIconLabel(baseImageUploadButtonEl, "bi-upload", "Upload");
        }

        baseImagesListEl.innerHTML = "";
        if (manager.loading) {
            const loading = document.createElement("div");
            loading.className = "text-body-secondary d-flex align-items-center gap-2 py-2";
            const spinner = document.createElement("span");
            spinner.className = "spinner-border spinner-border-sm";
            spinner.setAttribute("aria-hidden", "true");
            const label = document.createElement("span");
            label.textContent = "Loading base images...";
            loading.append(spinner, label);
            baseImagesListEl.appendChild(loading);
            return;
        }
        if (manager.images.length === 0) {
            const empty = document.createElement("div");
            empty.className = "alert alert-warning mb-0";
            empty.textContent = "No base images are available. Upload one before creating DevBoxes.";
            baseImagesListEl.appendChild(empty);
            return;
        }

        const list = document.createElement("div");
        list.className = "list-group";
        for (const name of manager.images) {
            const row = document.createElement("div");
            row.className = "list-group-item d-flex flex-wrap align-items-center justify-content-between gap-3";
            const fileName = document.createElement("span");
            fileName.className = "font-monospace text-break";
            fileName.textContent = name;
            const deleteButton = document.createElement("button");
            deleteButton.className = "btn btn-outline-danger btn-sm";
            deleteButton.type = "button";
            deleteButton.disabled = manager.busy;
            setIconLabel(
                deleteButton,
                manager.deleting === name ? "bi-hourglass-split" : "bi-trash",
                manager.deleting === name ? "Deleting..." : "Delete",
            );
            deleteButton.addEventListener("click", () => {
                void deleteManagedBaseImage(name);
            });
            row.append(fileName, deleteButton);
            list.appendChild(row);
        }
        baseImagesListEl.appendChild(list);
    }

    function openBaseImageManager(): void {
        if (!adminView) {
            return;
        }
        closeTerminal();
        closeVNC();
        if (state.create.open) {
            closeCreate();
        }
        closeInfo();
        state.baseImageManager.open = true;
        if (!state.baseImageManager.busy) {
            state.baseImageManager.error = "";
            state.baseImageManager.message = "";
        }
        renderBaseImageManager();
        (state.baseImageManager.busy ? baseImagesCloseEl : baseImageFileEl).focus();
        void loadManagedBaseImages();
    }

    function closeBaseImageManager(): void {
        const wasOpen = state.baseImageManager.open;
        state.baseImageManager.open = false;
        renderBaseImageManager();
        if (wasOpen) {
            baseImagesButtonEl.focus();
        }
    }

    function teardownTerminalRuntime(): void {
        terminalClosing = true;
        if (terminalResizeFrame) {
            window.cancelAnimationFrame(terminalResizeFrame);
            terminalResizeFrame = 0;
        }
        if (terminalInputDisposable) {
            terminalInputDisposable.dispose();
            terminalInputDisposable = null;
        }
        if (terminalSocket) {
            try {
                terminalSocket.close();
            } catch {
                // Ignore close errors during teardown.
            }
            terminalSocket = null;
        }
        if (terminalInstance) {
            terminalInstance.dispose();
            terminalInstance = null;
        }
        terminalFitAddon = null;
        terminalSurfaceEl.innerHTML = "";
    }

    function closeVNC(): void {
        state.vnc.open = false;
        state.vnc.vmName = "";
        state.vnc.vmDisplayName = "";
        state.vnc.src = "";
        renderVNC();
    }

    function renderInfo(): void {
        infoModalEl.hidden = !state.info.open;
        infoModalEl.setAttribute("aria-hidden", state.info.open ? "false" : "true");
        infoSubtitleEl.textContent = state.info.vmDisplayName || state.info.vmName;
        infoIPEl.textContent = state.info.ip || "n/a";
        infoUserEl.textContent = state.info.user || "n/a";
        infoImageEl.textContent = state.info.baseImage || "n/a";
        infoCreatedEl.textContent = formatCreatedAt(state.info.created);
        infoLastUsedEl.textContent = formatCreatedAt(state.info.lastUsed);
        infoAutoShutdownEl.textContent = formatAutoShutdown(state.info.lastUsed, state.info.vmState);
    }

    function setInfoFromVM(vm: DashboardVM): void {
        const ipValue = (vm.ip || "").trim();
        state.info.vmName = vm.name;
        state.info.vmDisplayName = vm.displayName || vm.name;
        state.info.ip = ipValue.toLowerCase() === "n/a" ? "" : ipValue;
        state.info.user = (vm.user || "").trim();
        state.info.baseImage = (vm.baseImage || "").trim();
        state.info.created = (vm.createdAt || "").trim();
        state.info.lastUsed = (vm.lastUsed || "").trim();
        state.info.vmState = (vm.state || "").trim();
    }

    function openInfo(vm: DashboardVM): void {
        state.info.open = true;
        setInfoFromVM(vm);
        renderInfo();
    }

    // refreshOpenInfo re-reads the open popup's VM from a fresh dashboard
    // snapshot so pushed updates (a state change, or a touch bumping the
    // last-used time and its auto-shutdown countdown) appear without the user
    // reopening the dialog. A VM that vanished from the list (deleted) keeps
    // its last known values until the dialog is closed.
    function refreshOpenInfo(): void {
        if (!state.info.open) {
            return;
        }
        const current = state.vms.find((vm) => (vm.name || "") === state.info.vmName);
        if (current) {
            setInfoFromVM(current);
        }
        renderInfo();
    }

    function closeInfo(): void {
        state.info.open = false;
        state.info.vmName = "";
        state.info.vmDisplayName = "";
        state.info.ip = "";
        state.info.user = "";
        state.info.baseImage = "";
        state.info.created = "";
        state.info.lastUsed = "";
        state.info.vmState = "";
        renderInfo();
    }

    function closeTerminal(): void {
        exitFullscreenIfNeeded(terminalDialogEl);
        teardownTerminalRuntime();
        state.terminal.open = false;
        state.terminal.vmName = "";
        state.terminal.vmDisplayName = "";
        state.terminal.status = "";
        state.terminal.error = "";
        renderTerminal();
    }

    function handleTerminalMessage(data: unknown): void {
        if (!terminalInstance) {
            return;
        }
        if (data instanceof ArrayBuffer) {
            terminalInstance.write(new Uint8Array(data));
            return;
        }
        if (data instanceof Blob) {
            void data.arrayBuffer().then((buffer) => {
                if (terminalInstance) {
                    terminalInstance.write(new Uint8Array(buffer));
                }
            });
            return;
        }
        if (typeof data === "string") {
            terminalInstance.write(data);
        }
    }

    function openTerminal(vm: DashboardVM): void {
        closeVNC();
        teardownTerminalRuntime();

        state.terminal.open = true;
        state.terminal.vmName = vm.name;
        state.terminal.vmDisplayName = vm.displayName || vm.name;
        state.terminal.status = "Connecting to guest serial console...";
        state.terminal.error = "";
        renderTerminal();

        if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
            state.terminal.status = "";
            state.terminal.error = "Terminal assets failed to load.";
            renderTerminal();
            return;
        }

        terminalClosing = false;
        terminalInstance = new Terminal({
            convertEol: true,
            cursorBlink: true,
            fontFamily: "'SFMono-Regular', 'Menlo', 'Monaco', monospace",
            fontSize: 14,
            theme: {
                background: "#0d1117",
                foreground: "#e6edf3",
                cursor: "#58a6ff",
                cursorAccent: "#0d1117",
                selectionBackground: "#264f78",
                black: "#484f58",
                red: "#ff7b72",
                green: "#3fb950",
                yellow: "#d29922",
                blue: "#58a6ff",
                magenta: "#bc8cff",
                cyan: "#39c5cf",
                white: "#b1bac4",
                brightBlack: "#6e7681",
                brightRed: "#ffa198",
                brightGreen: "#56d364",
                brightYellow: "#e3b341",
                brightBlue: "#79c0ff",
                brightMagenta: "#d2a8ff",
                brightCyan: "#56d4dd",
                brightWhite: "#f0f6fc",
            },
        });
        terminalFitAddon = new FitAddon.FitAddon();
        terminalInstance.loadAddon(terminalFitAddon);
        terminalInstance.open(terminalSurfaceEl);
        requestTerminalFit();
        terminalInstance.focus();

        const socket = new WebSocket(terminalWebSocketURL(vm.name));
        socket.binaryType = "arraybuffer";
        terminalSocket = socket;

        const encoder = new TextEncoder();
        const inputDisposable = terminalInstance.onData((data) => {
            if (terminalSocket !== socket || socket.readyState !== WebSocket.OPEN) {
                return;
            }
            socket.send(encoder.encode(data));
        });
        terminalInputDisposable = inputDisposable;

        socket.onopen = () => {
            if (terminalSocket !== socket) {
                return;
            }
            state.terminal.status = "Connected to guest serial console.";
            state.terminal.error = "";
            renderTerminal();
            requestTerminalFit();
        };

        socket.onmessage = (event: MessageEvent) => {
            if (terminalSocket !== socket) {
                return;
            }
            handleTerminalMessage(event.data);
        };

        socket.onerror = () => {
            if (terminalSocket !== socket) {
                return;
            }
            state.terminal.status = "";
            state.terminal.error = "Terminal connection failed.";
            renderTerminal();
        };

        socket.onclose = () => {
            if (terminalSocket === socket) {
                terminalSocket = null;
            }
            if (terminalInputDisposable === inputDisposable) {
                terminalInputDisposable.dispose();
                terminalInputDisposable = null;
            }
            if (terminalClosing || !state.terminal.open) {
                terminalClosing = false;
                return;
            }
            state.terminal.status = "Disconnected.";
            if (!state.terminal.error) {
                state.terminal.error = "Terminal connection closed.";
            }
            renderTerminal();
        };
    }

    function openVNC(vm: DashboardVM): void {
        closeTerminal();
        state.vnc.open = true;
        state.vnc.vmName = vm.name;
        state.vnc.vmDisplayName = vm.displayName || vm.name;
        state.vnc.src = vncFrameURL(vm.name);
        renderVNC();
    }

    function createInfoButton(vm: DashboardVM): HTMLButtonElement {
        const infoButton = document.createElement("button");
        infoButton.type = "button";
        infoButton.className = "btn btn-sm btn-outline-secondary";
        setIconLabel(infoButton, "bi-info-circle", "Info");
        infoButton.addEventListener("click", () => {
            openInfo(vm);
        });
        return infoButton;
    }

    // appendVMTable is shared by the personal dashboard and administrator
    // inventory. Capabilities stay independent so administrators get lifecycle
    // controls without gaining RDP, terminal, or noVNC access to another user's
    // VM.
    function appendVMTable(
        container: HTMLElement,
        vms: DashboardVM[],
        capabilities: VMTableCapabilities,
    ): void {
        const wrap = document.createElement("div");
        wrap.className = "table-responsive";
        const table = document.createElement("table");
        table.className = "table table-dark table-hover align-middle mb-0";
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        const columns = ["Name"];
        if (capabilities.connections) {
            columns.push("Connect");
        }
        columns.push("State", "Memory (GB)", "vCPU", "Disk");
        if (!capabilities.connections) {
            columns.push("Details");
        }
        if (capabilities.lifecycle) {
            columns.push("Actions");
        }
        for (const label of columns) {
            const th = document.createElement("th");
            th.scope = "col";
            th.textContent = label;
            headRow.appendChild(th);
        }
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        for (const vm of vms) {
            const row = document.createElement("tr");
            const rawName = vm.name || "";
            const displayName = vm.displayName || rawName;
            const normalizedState = (vm.state || "").trim().toLowerCase();
            const rdpReady = Boolean(vm.rdpReady);
            const hasName = rawName.trim() !== "";
            const isActive = isActiveState(normalizedState);
            const isBooting = capabilities.connections && normalizedState === "running" && !rdpReady;

            const nameCell = document.createElement("td");
            nameCell.className = "fw-semibold";
            nameCell.textContent = displayName || "n/a";
            row.appendChild(nameCell);

            if (capabilities.connections) {
                const connectCell = document.createElement("td");
                connectCell.className = "align-top";
                if (hasName) {
                    const connectStack = document.createElement("div");
                    connectStack.className = "d-flex flex-column gap-2";
                    const connectActions = document.createElement("div");
                    connectActions.className = "d-flex flex-wrap gap-2";

                    if (displayName.trim() !== "") {
                        const connectButton = document.createElement("button");
                        connectButton.type = "button";
                        connectButton.className = rdpReady
                            ? "btn btn-sm btn-success"
                            : "btn btn-sm btn-outline-secondary";
                        setIconLabel(connectButton, "bi-display", "RDP");
                        connectButton.disabled = state.busy || !rdpReady;
                        if (rdpReady) {
                            // Clicking RDP POSTs to the server, which opens a
                            // short-lived authorization window and returns the
                            // .rdp file. The file alone is not enough to connect.
                            connectButton.addEventListener("click", () => {
                                void connectRDP(vm);
                            });
                        } else {
                            connectButton.title = "RDP is unavailable until this DevBox is ready.";
                        }
                        connectActions.appendChild(connectButton);
                    }

                    const terminalButton = document.createElement("button");
                    terminalButton.type = "button";
                    terminalButton.className = "btn btn-sm btn-outline-info";
                    setIconLabel(terminalButton, "bi-terminal", "Terminal");
                    terminalButton.disabled = state.busy || !isActive;
                    terminalButton.addEventListener("click", () => {
                        openTerminal(vm);
                    });
                    connectActions.appendChild(terminalButton);

                    const vncButton = document.createElement("button");
                    vncButton.type = "button";
                    vncButton.className = "btn btn-sm btn-outline-primary";
                    setIconLabel(vncButton, "bi-window-desktop", "NoVNC");
                    vncButton.disabled = state.busy || !isActive;
                    vncButton.addEventListener("click", () => {
                        openVNC(vm);
                    });
                    connectActions.appendChild(vncButton);
                    connectActions.appendChild(createInfoButton(vm));
                    connectStack.appendChild(connectActions);
                    connectCell.appendChild(connectStack);
                } else {
                    connectCell.textContent = "n/a";
                    connectCell.classList.add("text-body-secondary");
                }
                row.appendChild(connectCell);
            }

            const stateCell = document.createElement("td");
            const stateBadge = document.createElement("span");
            let stateClass = "text-bg-secondary";
            if (normalizedState === "running" && (!capabilities.connections || rdpReady)) {
                stateClass = "text-bg-success";
            } else if (isBooting || normalizedState === "paused") {
                stateClass = "text-bg-warning";
            } else if (normalizedState === "suspended") {
                stateClass = "text-bg-danger";
            }
            const stateText = isBooting ? "booting" : normalizedState ? (vm.state || "").trim() : "n/a";
            stateBadge.className = `badge ${stateClass}`;
            if (normalizedState) {
                stateBadge.classList.add("text-capitalize");
            }
            stateBadge.textContent = stateText;
            stateCell.appendChild(stateBadge);
            row.appendChild(stateCell);

            const memoryCell = document.createElement("td");
            memoryCell.textContent = formatMemoryGB(vm.memoryMiB);
            row.appendChild(memoryCell);

            const vcpuCell = document.createElement("td");
            vcpuCell.textContent = vm.vcpu ? `${vm.vcpu}` : "n/a";
            row.appendChild(vcpuCell);

            const diskCell = document.createElement("td");
            diskCell.textContent = vm.volumeGB ? `${vm.volumeGB} GB` : "n/a";
            row.appendChild(diskCell);

            if (!capabilities.connections) {
                const detailsCell = document.createElement("td");
                detailsCell.className = "align-top";
                detailsCell.appendChild(createInfoButton(vm));
                row.appendChild(detailsCell);
            }

            if (capabilities.lifecycle) {
                const actionCell = document.createElement("td");
                actionCell.className = "align-top";
                const actionStack = document.createElement("div");
                actionStack.className = "d-flex flex-column gap-2";
                const actions = document.createElement("div");
                actions.className = "d-flex flex-wrap gap-2";

                const startButton = document.createElement("button");
                startButton.type = "button";
                startButton.className = "btn btn-sm btn-outline-success";
                setIconLabel(startButton, "bi-play-fill", "Start");
                startButton.disabled = state.busy || !hasName || isActive;
                startButton.addEventListener("click", () => {
                    void startVM(rawName);
                });
                actions.appendChild(startButton);

                const restartButton = document.createElement("button");
                restartButton.type = "button";
                restartButton.className = "btn btn-sm btn-outline-secondary";
                setIconLabel(restartButton, "bi-arrow-clockwise", "Restart");
                restartButton.disabled = state.busy || !hasName || !isActive;
                restartButton.addEventListener("click", () => {
                    void restartVM(rawName);
                });
                actions.appendChild(restartButton);

                const shutdownButton = document.createElement("button");
                shutdownButton.type = "button";
                shutdownButton.className = "btn btn-sm btn-outline-warning";
                setIconLabel(shutdownButton, "bi-stop-fill", "Stop");
                shutdownButton.disabled = state.busy || !hasName || !isActive;
                shutdownButton.addEventListener("click", () => {
                    void shutdownVM(rawName);
                });
                actions.appendChild(shutdownButton);

                const removeButton = document.createElement("button");
                removeButton.type = "button";
                removeButton.className = "btn btn-sm btn-outline-danger";
                setIconLabel(removeButton, "bi-trash", "Remove");
                removeButton.disabled = state.busy || !hasName;
                removeButton.addEventListener("click", () => {
                    if (!confirmRemoval(rawName)) {
                        return;
                    }
                    void removeVM(rawName);
                });
                actions.appendChild(removeButton);
                actionStack.appendChild(actions);
                actionCell.appendChild(actionStack);
                row.appendChild(actionCell);
            }
            tbody.appendChild(row);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        container.appendChild(wrap);
    }

    function renderAdminVMGroups(): void {
        const vmsByOwner = new Map<string, DashboardVM[]>();
        for (const vm of state.vms) {
            const owner = (vm.owner || "").trim();
            const ownerVMs = vmsByOwner.get(owner);
            if (ownerVMs) {
                ownerVMs.push(vm);
            } else {
                vmsByOwner.set(owner, [vm]);
            }
        }

        // Named owners sort first; VMs without owner metadata remain visible in
        // an explicit final group instead of disappearing from the admin view.
        const owners = Array.from(vmsByOwner.keys()).sort((left, right) => {
            if (left === "") {
                return right === "" ? 0 : 1;
            }
            if (right === "") {
                return -1;
            }
            return left.localeCompare(right);
        });
        for (const owner of owners) {
            const section = document.createElement("section");
            section.className = "mb-4";
            const heading = document.createElement("h2");
            heading.className = "h5 mb-2";
            heading.textContent = owner === "" ? "Unowned" : `User: ${owner}`;
            section.appendChild(heading);
            appendVMTable(section, vmsByOwner.get(owner) || [], { connections: false, lifecycle: true });
            listAreaEl.appendChild(section);
        }
    }

    function renderVMList(): void {
        listAreaEl.innerHTML = "";
        if (state.loading) {
            const loading = document.createElement("div");
            loading.className = "d-flex align-items-center gap-2 text-body-secondary";
            const spinner = document.createElement("div");
            spinner.className = "spinner-border spinner-border-sm";
            spinner.setAttribute("role", "status");
            spinner.setAttribute("aria-hidden", "true");
            const text = document.createElement("span");
            text.textContent = "Loading virtual machines...";
            loading.appendChild(spinner);
            loading.appendChild(text);
            listAreaEl.appendChild(loading);
            return;
        }
        if (state.vmError) {
            const error = document.createElement("div");
            error.className = "alert alert-danger mb-0";
            error.setAttribute("role", "alert");
            error.textContent = state.vmError;
            listAreaEl.appendChild(error);
            return;
        }
        if (state.vms.length === 0) {
            const empty = document.createElement("div");
            empty.className = "text-body-secondary";
            empty.textContent = "No virtual machines found.";
            listAreaEl.appendChild(empty);
            return;
        }

        if (adminView) {
            renderAdminVMGroups();
            return;
        }
        appendVMTable(listAreaEl, state.vms, { connections: true, lifecycle: true });
    }

    // updateCreateAvailability keeps the base image picker and the create button
    // disabled while busy or when the gateway offers no base images to clone.
    function updateCreateAvailability(): void {
        const noImages = baseImages.length === 0;
        baseImageSelectEl.disabled = state.busy || noImages;
        createButtonEl.disabled = state.busy || noImages;
    }

    // renderBaseImageOptions rebuilds the picker from the latest list, preserving
    // a still-valid selection. An empty list shows a disabled placeholder so the
    // required field blocks submission.
    function renderBaseImageOptions(): void {
        const previous = baseImageSelectEl.value;
        baseImageSelectEl.innerHTML = "";
        if (baseImages.length === 0) {
            const option = document.createElement("option");
            option.value = "";
            option.textContent = "No base images available";
            option.disabled = true;
            option.selected = true;
            baseImageSelectEl.appendChild(option);
            updateCreateAvailability();
            return;
        }
        for (const image of baseImages) {
            const option = document.createElement("option");
            option.value = image;
            option.textContent = image;
            baseImageSelectEl.appendChild(option);
        }
        if (baseImages.includes(previous)) {
            baseImageSelectEl.value = previous;
        }
        updateCreateAvailability();
    }

    function setBusy(isBusy: boolean): void {
        state.busy = isBusy;
        inputEl.disabled = isBusy;
        usernameInputEl.disabled = isBusy;
        updateCreateAvailability();
        renderVMList();
    }

    function setActionError(message: string): void {
        state.actionError = message;
        state.actionMessage = "";
        renderAction();
    }

    function setActionMessage(message: string): void {
        state.actionMessage = message;
        state.actionError = "";
        renderAction();
    }

    function clearAction(): void {
        state.actionError = "";
        state.actionMessage = "";
        renderAction();
    }

    function confirmRemoval(name: string): boolean {
        const trimmed = name.trim();
        if (!trimmed) {
            setActionError("Unable to remove VM: missing name.");
            return false;
        }
        const response = window.prompt(`Type the VM name "${trimmed}" to confirm removal:`);
        if (response === null) {
            return false;
        }
        if (response.trim() !== trimmed) {
            setActionError("Removal canceled: name did not match.");
            return false;
        }
        return true;
    }

    function applyInitialMessage(): void {
        const params = new URLSearchParams(window.location.search);
        if (params.has("removed")) {
            setActionMessage("VM removed.");
            params.delete("removed");
        } else if (params.has("created")) {
            setActionMessage("VM creation started.");
            params.delete("created");
        }
        if (params.toString() !== window.location.search.replace(/^\?/, "")) {
            const query = params.toString();
            const next = query ? `${window.location.pathname}?${query}` : window.location.pathname;
            window.history.replaceState({}, "", next);
        }
    }

    function redirectToLogin(): null {
        state.vms = [];
        state.vmError = "";
        state.loading = true;
        clearAction();
        closeTerminal();
        closeVNC();
        state.baseImageManager.open = false;
        renderBaseImageManager();
        renderVMList();
        window.location.replace(LOGIN_PATH);
        return null;
    }

    function responseRequiresLogin(response: Response): boolean {
        if (response.status === 401) {
            return true;
        }

        try {
            const finalUrl = new URL(response.url, window.location.origin);
            return finalUrl.pathname === LOGIN_PATH;
        } catch {
            return false;
        }
    }

    async function requestJSON<T>(url: string, init: RequestInit = {}): Promise<RequestResult<T> | null> {
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        let response: Response;
        try {
            response = await fetch(url, {
                ...init,
                cache: "no-store",
                headers,
                credentials: "same-origin",
            });
        } catch {
            return { ok: false, error: SESSION_CHECK_ERROR };
        }
        if (responseRequiresLogin(response)) {
            return redirectToLogin();
        }
        let payload: any = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }
        if (!response.ok) {
            const errorMessage = payload && typeof payload.error === "string"
                ? payload.error
                : "Request failed.";
            return { ok: false, error: errorMessage };
        }
        return { ok: true, data: payload as T };
    }

    async function readCreationStream(response: Response): Promise<RequestResult<DashboardActionResponse>> {
        if (!response.body) {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffered = "";
        const streamState: {
            result: DashboardActionResponse | null;
            invalidResponse: boolean;
        } = {
            result: null,
            invalidResponse: false,
        };

        function consumeLine(rawLine: string): void {
            const line = rawLine.trim();
            if (line === "") {
                return;
            }

            let event: DashboardCreationStreamEvent;
            try {
                const parsed = JSON.parse(line);
                if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                    streamState.invalidResponse = true;
                    return;
                }
                event = parsed as DashboardCreationStreamEvent;
            } catch {
                streamState.invalidResponse = true;
                return;
            }

            if (event.type === "progress") {
                if (typeof event.copiedBytes === "number" && typeof event.totalBytes === "number") {
                    updateCreateDiskProgress(event.copiedBytes, event.totalBytes);
                }
                return;
            }
            if (event.type === "result") {
                streamState.result = {
                    ok: event.ok === true,
                    message: typeof event.message === "string" ? event.message : undefined,
                    error: typeof event.error === "string" ? event.error : undefined,
                };
            }
            // Ignore unknown event types so newer servers can add optional frames.
        }

        try {
            streamLoop:
            while (true) {
                const { done, value } = await reader.read();
                if (value) {
                    buffered += decoder.decode(value, { stream: true });
                }

                let newline = buffered.indexOf("\n");
                while (newline >= 0) {
                    consumeLine(buffered.slice(0, newline));
                    buffered = buffered.slice(newline + 1);
                    if (streamState.result) {
                        break streamLoop;
                    }
                    newline = buffered.indexOf("\n");
                }

                if (done) {
                    buffered += decoder.decode();
                    consumeLine(buffered);
                    break;
                }
            }
        } catch {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }

        if (streamState.result) {
            try {
                await reader.cancel();
            } catch {
                // A complete result remains authoritative if stream cleanup fails.
            }
        }

        if (streamState.invalidResponse) {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }
        const result = streamState.result;
        if (!result) {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }
        if (!response.ok) {
            return { ok: false, error: result.error || "Failed to create VM." };
        }
        return { ok: true, data: result };
    }

    async function requestVMCreation(body: URLSearchParams): Promise<RequestResult<DashboardActionResponse> | null> {
        let response: Response;
        try {
            response = await fetch("/api/dashboard", {
                method: "POST",
                cache: "no-store",
                credentials: "same-origin",
                headers: {
                    "Accept": "application/x-ndjson, application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: body.toString(),
            });
        } catch {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }
        if (responseRequiresLogin(response)) {
            return redirectToLogin();
        }

        const mediaType = (response.headers.get("Content-Type") || "")
            .split(";", 1)[0]
            .trim()
            .toLowerCase();
        if (mediaType === "application/x-ndjson") {
            return readCreationStream(response);
        }

        // Older gateways return one JSON action response after provisioning.
        let payload: any = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }
        if (!response.ok) {
            const errorMessage = payload && typeof payload.error === "string"
                ? payload.error
                : "Failed to create VM.";
            return { ok: false, error: errorMessage };
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.ok !== "boolean") {
            return { ok: false, error: CREATION_STATUS_UNKNOWN_ERROR };
        }
        return { ok: true, data: payload as DashboardActionResponse };
    }

    async function loadManagedBaseImages(): Promise<void> {
        const manager = state.baseImageManager;
        if (manager.loading) {
            return;
        }
        manager.loading = true;
        renderBaseImageManager();
        try {
            const result = await requestJSON<AdminBaseImagesResponse>(ADMIN_BASE_IMAGES_PATH);
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                manager.error = result.error || "Unable to load base images right now.";
                return;
            }
            manager.images = Array.isArray(result.data.baseImages)
                ? result.data.baseImages.filter((name): name is string => typeof name === "string")
                : [];
            manager.maxUploadBytes = typeof result.data.maxUploadBytes === "number"
                ? result.data.maxUploadBytes
                : 0;
            manager.availableStorageBytes = typeof result.data.availableStorageBytes === "number" &&
                Number.isFinite(result.data.availableStorageBytes) && result.data.availableStorageBytes >= 0
                ? result.data.availableStorageBytes
                : null;
        } finally {
            manager.loading = false;
            renderBaseImageManager();
        }
    }

    function requestBaseImageUpload(file: File): Promise<RequestResult<DashboardActionResponse> | null> {
        return new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            const body = new FormData();
            body.append("base_image", file, file.name);
            xhr.open("POST", ADMIN_BASE_IMAGES_PATH);
            xhr.setRequestHeader("Accept", "application/json");
            xhr.withCredentials = true;

            xhr.upload.onprogress = (event) => {
                if (!state.baseImageManager.busy || state.baseImageManager.deleting !== "") {
                    return;
                }
                state.baseImageManager.phase = "uploading";
                state.baseImageManager.percent = event.lengthComputable && event.total > 0
                    ? Math.max(0, Math.min(100, event.loaded / event.total * 100))
                    : null;
                renderBaseImageManager();
            };
            xhr.upload.onload = () => {
                if (!state.baseImageManager.busy || state.baseImageManager.deleting !== "") {
                    return;
                }
                state.baseImageManager.phase = "finalizing";
                state.baseImageManager.percent = 100;
                renderBaseImageManager();
            };
            xhr.onerror = () => {
                resolve({ ok: false, error: "The base image upload was interrupted." });
            };
            xhr.onabort = () => {
                resolve({ ok: false, error: "The base image upload was canceled." });
            };
            xhr.onload = () => {
                let loginRequired = xhr.status === HTTP_STATUS_UNAUTHORIZED;
                try {
                    const finalUrl = new URL(xhr.responseURL, window.location.origin);
                    loginRequired = loginRequired || finalUrl.pathname === LOGIN_PATH;
                } catch {
                    // Keep the status-based result when the browser omits responseURL.
                }
                if (loginRequired) {
                    resolve(redirectToLogin());
                    return;
                }

                let payload: any = null;
                try {
                    payload = JSON.parse(xhr.responseText);
                } catch {
                    payload = null;
                }
                if (xhr.status < 200 || xhr.status >= 300) {
                    const message = payload && typeof payload.error === "string"
                        ? payload.error
                        : "Base image upload failed.";
                    resolve({ ok: false, error: message });
                    return;
                }
                resolve({ ok: true, data: payload as DashboardActionResponse });
            };
            xhr.send(body);
        });
    }

    async function uploadManagedBaseImage(file: File): Promise<void> {
        const manager = state.baseImageManager;
        if (manager.busy) {
            return;
        }
        if (file.size === 0) {
            manager.error = "Base image files cannot be empty.";
            manager.message = "";
            renderBaseImageManager();
            return;
        }
        if (manager.maxUploadBytes > 0 && file.size > manager.maxUploadBytes) {
            manager.error = `The selected file exceeds the ${formatBytes(manager.maxUploadBytes)} upload limit.`;
            manager.message = "";
            renderBaseImageManager();
            return;
        }

        manager.busy = true;
        manager.phase = "uploading";
        manager.percent = null;
        manager.deleting = "";
        manager.error = "";
        manager.message = "";
        renderBaseImageManager();
        try {
            const result = await requestBaseImageUpload(file);
            if (!result) {
                return;
            }
            if (!result.ok || !result.data || result.data.ok !== true) {
                manager.error = result.error || result.data?.error || "Base image upload failed.";
                return;
            }
            manager.message = result.data.message || "Base image uploaded.";
            baseImageFileEl.value = "";
            await loadManagedBaseImages();
        } finally {
            manager.busy = false;
            manager.phase = "idle";
            manager.percent = null;
            renderBaseImageManager();
        }
    }

    async function deleteManagedBaseImage(name: string): Promise<void> {
        const manager = state.baseImageManager;
        if (manager.busy) {
            return;
        }
        const confirmation = window.prompt(`Type the base image name "${name}" to confirm deletion:`);
        if (confirmation === null) {
            return;
        }
        if (confirmation !== name) {
            manager.error = "Deletion canceled: name did not match.";
            manager.message = "";
            renderBaseImageManager();
            return;
        }

        manager.busy = true;
        manager.deleting = name;
        manager.error = "";
        manager.message = "";
        renderBaseImageManager();
        try {
            const body = new URLSearchParams({ base_image: name });
            const result = await requestJSON<DashboardActionResponse>(ADMIN_BASE_IMAGES_DELETE_PATH, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
            });
            if (!result) {
                return;
            }
            if (!result.ok || !result.data || result.data.ok !== true) {
                manager.error = result.error || result.data?.error || "Base image deletion failed.";
                return;
            }
            manager.message = result.data.message || "Base image deleted.";
            await loadManagedBaseImages();
        } finally {
            manager.busy = false;
            manager.deleting = "";
            renderBaseImageManager();
        }
    }

    async function loadVMs(): Promise<void> {
        if (loadInFlight) {
            return;
        }
        loadInFlight = true;
        state.loading = true;
        state.vmError = "";
        renderVMList();
        try {
            const result = await requestJSON<DashboardDataResponse>(dashboardDataURL());
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                state.vms = [];
                state.vmError = result.error || DEFAULT_VM_ERROR;
                return;
            }
            applyDashboardData(result.data);
        } finally {
            state.loading = false;
            renderVMList();
            loadInFlight = false;
        }
    }

    async function createVM(name: string, username: string, baseImage: string): Promise<void> {
        if (state.busy) {
            return;
        }
        clearAction();
        setCreateError("");
        beginCreateProgress();
        setBusy(true);
        let closeOnFinish = false;
        try {
            // No password fields: the server provisions the DevBox account with
            // the (hashed) gateway login password held in the session.
            const body = new URLSearchParams({
                vm_name: name,
                vm_username: username,
                vm_base_image: baseImage,
            });
            const result = await requestVMCreation(body);
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                state.create.open = true;
                setCreateError(result.error || "Failed to create VM.");
                return;
            }
            if (!result.data.ok) {
                state.create.open = true;
                setCreateError(result.data.error || "Failed to create VM.");
                return;
            }
            setActionMessage(result.data.message || "VM created.");
            inputEl.value = "";
            usernameInputEl.value = defaultUsername;
            closeOnFinish = true;
        } catch {
            state.create.open = true;
            setCreateError(CREATION_STATUS_UNKNOWN_ERROR);
        } finally {
            finishCreateProgress();
            setBusy(false);
            if (closeOnFinish) {
                closeCreate();
            }
        }
    }

    async function actionVM(
        name: string,
        url: string,
        successMessage: string,
        failureMessage: string,
    ): Promise<void> {
        if (state.busy) {
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({ vm_name: name });
            const result = await requestJSON<DashboardActionResponse>(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: body.toString(),
            });
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                setActionError(result.error || failureMessage);
                return;
            }
            if (!result.data.ok) {
                setActionError(result.data.error || failureMessage);
                return;
            }
            setActionMessage(result.data.message || successMessage);
        } finally {
            setBusy(false);
        }
    }

    async function removeVM(name: string): Promise<void> {
        await actionVM(name, "/api/dashboard/remove", "VM removed.", "Failed to remove VM.");
    }

    async function startVM(name: string): Promise<void> {
        await actionVM(name, "/api/dashboard/start", "VM start requested.", "Failed to start VM.");
    }

    async function restartVM(name: string): Promise<void> {
        await actionVM(name, "/api/dashboard/restart", "VM restart requested.", "Failed to restart VM.");
    }

    async function shutdownVM(name: string): Promise<void> {
        await actionVM(name, "/api/dashboard/shutdown", "VM stop requested.", "Failed to stop VM.");
    }

    function filenameFromContentDisposition(header: string | null, fallback: string): string {
        if (header) {
            const match = /filename="?([^";]+)"?/i.exec(header);
            if (match && match[1].trim() !== "") {
                return match[1].trim();
            }
        }
        return fallback;
    }

    function triggerBlobDownload(blob: Blob, filename: string): void {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        // Revoke after a tick so the browser has started the download.
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // connectRDP is the "Connect" action: it asks the server to authorize an RDP
    // connection for this VM (opening a short-lived window keyed to the user's
    // IP) and download the matching .rdp file. On success the file is saved; the
    // user then opens it in their RDP client within the authorization window.
    async function connectRDP(vm: DashboardVM): Promise<void> {
        if (state.busy) {
            return;
        }
        const name = (vm.name || "").trim();
        if (name === "") {
            setActionError("Unable to connect: missing VM name.");
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({ vm_name: name });
            let response: Response;
            try {
                response = await fetch("/api/dashboard/rdp", {
                    method: "POST",
                    cache: "no-store",
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body: body.toString(),
                });
            } catch {
                setActionError(SESSION_CHECK_ERROR);
                return;
            }
            if (responseRequiresLogin(response)) {
                redirectToLogin();
                return;
            }
            if (!response.ok) {
                let message = "Failed to start RDP connection.";
                try {
                    const payload = await response.json();
                    if (payload && typeof payload.error === "string" && payload.error !== "") {
                        message = payload.error;
                    }
                } catch {
                    // Non-JSON error body: keep the default message.
                }
                setActionError(message);
                return;
            }
            const blob = await response.blob();
            const filename = filenameFromContentDisposition(
                response.headers.get("Content-Disposition"),
                vm.rdpFilename || state.filename,
            );
            triggerBlobDownload(blob, filename);
            setActionMessage("RDP connection authorized. Open the downloaded .rdp file to connect within 2 minutes.");
        } finally {
            setBusy(false);
        }
    }

    formEl.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!formEl.reportValidity()) {
            return;
        }
        void createVM(
            inputEl.value.trim(),
            usernameInputEl.value.trim(),
            baseImageSelectEl.value,
        );
    });

    terminalBackdropEl.addEventListener("click", () => {
        closeTerminal();
    });

    terminalCloseEl.addEventListener("click", () => {
        closeTerminal();
    });

    terminalFullscreenEl.addEventListener("click", () => {
        void toggleFullscreen(terminalDialogEl);
    });

    vncBackdropEl.addEventListener("click", () => {
        closeVNC();
    });

    vncCloseEl.addEventListener("click", () => {
        closeVNC();
    });

    openCreateButtonEl.addEventListener("click", () => {
        openCreate();
    });

    baseImagesButtonEl.addEventListener("click", () => {
        openBaseImageManager();
    });

    baseImagesBackdropEl.addEventListener("click", () => {
        closeBaseImageManager();
    });

    baseImagesCloseEl.addEventListener("click", () => {
        closeBaseImageManager();
    });

    baseImageUploadFormEl.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!baseImageUploadFormEl.reportValidity()) {
            return;
        }
        const file = baseImageFileEl.files?.item(0);
        if (!file) {
            state.baseImageManager.error = "Choose a base image to upload.";
            state.baseImageManager.message = "";
            renderBaseImageManager();
            return;
        }
        void uploadManagedBaseImage(file);
    });

    createBackdropEl.addEventListener("click", () => {
        closeCreate();
    });

    createCloseEl.addEventListener("click", () => {
        closeCreate();
    });

    infoBackdropEl.addEventListener("click", () => {
        closeInfo();
    });

    infoCloseEl.addEventListener("click", () => {
        closeInfo();
    });

    // Keep the auto-shutdown countdown in the open Info dialog ticking even
    // when no dashboard push arrives; renderInfo recomputes it from the
    // last-used timestamp each time.
    window.setInterval(() => {
        if (state.info.open) {
            renderInfo();
        }
    }, 30000);

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && state.baseImageManager.open) {
            closeBaseImageManager();
            return;
        }
        if (event.key === "Escape" && state.info.open) {
            closeInfo();
            return;
        }
        if (event.key === "Escape" && state.create.open) {
            closeCreate();
            return;
        }
        if (event.key === "Escape" && state.terminal.open) {
            closeTerminal();
            return;
        }
        if (event.key === "Escape" && state.vnc.open) {
            closeVNC();
        }
    });

    window.addEventListener("resize", () => {
        requestTerminalFit();
    });

    document.addEventListener("fullscreenchange", () => {
        renderTerminal();
        requestTerminalFit();
    });

    applyInitialMessage();
    renderAction();
    renderVMList();
    renderTerminal();
    renderVNC();
    renderCreate();
    renderBaseImageManager();
    updateCreateAvailability();
    renderRTT(null, null);
    renderServerMemory(null);
    renderServerDisk(null);
    renderServerDiskIO(null);
    renderServerCPU(null);
    void loadVMs().then(() => {
        dashboardInitialLoadComplete = true;
        connectDashboardSocket();
    });

    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) {
            // Re-probe immediately on return; reconnect if the socket dropped.
            if (dashboardInitialLoadComplete) {
                connectDashboardSocket();
            }
            sendRTTProbe();
        }
    });

    window.addEventListener("pageshow", (event) => {
        if (event.persisted && dashboardInitialLoadComplete) {
            connectDashboardSocket();
        }
    });

    window.addEventListener("beforeunload", () => {
        teardownDashboardSocket();
        terminalResizeObserver.disconnect();
        teardownTerminalRuntime();
        closeVNC();
    });
}

bootstrap();
