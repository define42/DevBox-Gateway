"use strict";
// Source for the dashboard UI. Run "tsc -p tsconfig.json" to update static/dashboard.js.
const DEFAULT_VM_ERROR = "Unable to load virtual machines right now.";
const SESSION_CHECK_ERROR = "Unable to verify your session. Reload and sign in again.";
const AUTO_REFRESH_INTERVAL_MS = 10000;
const DEFAULT_VCPU = "4";
const DEFAULT_MEMORY_MIB = "4096";
const LOGIN_PATH = "/login";
const VCPU_OPTIONS = ["1", "2", "4", "8"];
const MEMORY_OPTIONS = ["4096", "8192", "16384", "32768"];
const state = {
    vms: [],
    filename: "rdpgw.rdp",
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
    },
    info: {
        open: false,
        vmName: "",
        vmDisplayName: "",
        ip: "",
        user: "",
        baseImage: "",
        created: "",
    },
};
let loadInFlight = false;
function isActiveState(vmState) {
    const normalized = vmState.trim().toLowerCase();
    return normalized === "running" || normalized === "paused" || normalized === "suspended";
}
function formatMemoryGB(memoryMiB) {
    if (!memoryMiB) {
        return "n/a";
    }
    const gb = Number(memoryMiB) / 1024;
    const formatted = Number.isInteger(gb) ? gb.toFixed(0) : gb.toFixed(1);
    return `${formatted} GB`;
}
// formatCreatedAt turns the RFC3339 UTC timestamp stored on the VM into a
// human-readable local date/time. Unparseable or empty values fall back to a
// placeholder so older VMs without the metadata still render cleanly.
function formatCreatedAt(createdAt) {
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
// setIconLabel renders a Bootstrap Icon followed by a text label inside a button
// (or anchor). Labels are static, but we build the nodes explicitly rather than
// using innerHTML to keep the rendering path free of HTML string injection.
function setIconLabel(el, iconClass, label) {
    el.textContent = "";
    const icon = document.createElement("i");
    icon.className = `bi ${iconClass} me-1`;
    icon.setAttribute("aria-hidden", "true");
    el.append(icon, label);
}
function buildSelect(options, selectedValue, labelFn) {
    const select = document.createElement("select");
    for (const value of options) {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = labelFn(value);
        if (String(value) === String(selectedValue)) {
            option.selected = true;
        }
        select.appendChild(option);
    }
    return select;
}
function terminalWebSocketURL(name) {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}/api/dashboard/console/${encodeURIComponent(name)}/ws`;
}
function vncFrameURL(name) {
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
function bootstrap() {
    const root = document.getElementById("app");
    if (!root) {
        return;
    }
    root.innerHTML = `
    <main class="container py-4">
      <div class="card shadow-sm">
        <div class="card-body">
          <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-4">
            <div>
              <h1 class="h4 mb-1">Available DevBoxes</h1>
              <p class="text-body-secondary mb-0">Live inventory.</p>
            </div>
            <div class="d-flex flex-wrap align-items-center gap-2">
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
            <dd class="col-8 col-sm-9 mb-0" id="info-created"></dd>
          </dl>
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
              <input class="form-control" id="vm-username" name="vm_username" autocomplete="off" pattern="[a-z_][a-z0-9_-]*" maxlength="32" title="Login user created inside the DevBox. Lowercase letters, numbers, hyphens, or underscores. Must start with a letter or underscore. Max 32 characters." autocapitalize="none" spellcheck="false">
            </div>
            <div class="col-12 col-md-6 col-lg-6">
              <label class="form-label" for="vm-password">Password</label>
              <input class="form-control" id="vm-password" name="vm_password" type="password" autocomplete="new-password" maxlength="128" title="Password for the account created inside the DevBox. Max 128 characters." autocapitalize="none" spellcheck="false" required>
            </div>
            <div class="col-12 col-md-6 col-lg-6">
              <label class="form-label" for="vm-password-confirm">Confirm Password</label>
              <input class="form-control" id="vm-password-confirm" name="vm_password_confirm" type="password" autocomplete="new-password" maxlength="128" title="Re-enter the password to confirm it matches." autocapitalize="none" spellcheck="false" required>
            </div>
            <div class="col-6 col-lg-4">
              <label class="form-label" for="vm-cpu">vCPU</label>
              <select class="form-select" id="vm-cpu" name="vm_vcpu" required>
                <option value="1">1 vCPU</option>
                <option value="2">2 vCPU</option>
                <option value="4" selected>4 vCPU</option>
                <option value="8">8 vCPU</option>
              </select>
            </div>
            <div class="col-6 col-lg-4">
              <label class="form-label" for="vm-memory">Memory</label>
              <select class="form-select" id="vm-memory" name="vm_memory_mib" required>
                <option value="4096" selected>4 GB</option>
                <option value="8192">8 GB</option>
                <option value="16384">16 GB</option>
                <option value="32768">32 GB</option>
              </select>
            </div>
            <div class="col-12 col-md-6 col-lg-4 d-grid align-self-end">
              <button class="btn btn-primary" id="create-button" type="submit"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i>Create DevBox</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  `;
    const form = root.querySelector("#create-form");
    const input = root.querySelector("#vm-name");
    const usernameInput = root.querySelector("#vm-username");
    const passwordInput = root.querySelector("#vm-password");
    const passwordConfirmInput = root.querySelector("#vm-password-confirm");
    const cpuSelect = root.querySelector("#vm-cpu");
    const memorySelect = root.querySelector("#vm-memory");
    const baseImageSelect = root.querySelector("#vm-base-image");
    const createButton = root.querySelector("#create-button");
    const actionArea = root.querySelector("#action-area");
    const listArea = root.querySelector("#vm-list");
    const terminalModal = root.querySelector("#terminal-modal");
    const terminalBackdrop = root.querySelector("#terminal-backdrop");
    const terminalDialog = root.querySelector("#terminal-dialog");
    const terminalSubtitle = root.querySelector("#terminal-subtitle");
    const terminalStatus = root.querySelector("#terminal-status");
    const terminalError = root.querySelector("#terminal-error");
    const terminalSurface = root.querySelector("#terminal-surface");
    const terminalFullscreen = root.querySelector("#terminal-fullscreen");
    const terminalClose = root.querySelector("#terminal-close");
    const vncModal = root.querySelector("#vnc-modal");
    const vncBackdrop = root.querySelector("#vnc-backdrop");
    const vncDialog = root.querySelector("#vnc-dialog");
    const vncSubtitle = root.querySelector("#vnc-subtitle");
    const vncFrame = root.querySelector("#vnc-frame");
    const vncClose = root.querySelector("#vnc-close");
    const openCreateButton = root.querySelector("#open-create-button");
    const createModal = root.querySelector("#create-modal");
    const createBackdrop = root.querySelector("#create-backdrop");
    const createClose = root.querySelector("#create-close");
    const createError = root.querySelector("#create-error");
    const infoModal = root.querySelector("#info-modal");
    const infoBackdrop = root.querySelector("#info-backdrop");
    const infoSubtitle = root.querySelector("#info-subtitle");
    const infoIP = root.querySelector("#info-ip");
    const infoUser = root.querySelector("#info-user");
    const infoImage = root.querySelector("#info-image");
    const infoCreated = root.querySelector("#info-created");
    const infoClose = root.querySelector("#info-close");
    if (!form ||
        !input ||
        !usernameInput ||
        !passwordInput ||
        !passwordConfirmInput ||
        !cpuSelect ||
        !memorySelect ||
        !baseImageSelect ||
        !createButton ||
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
        !infoModal ||
        !infoBackdrop ||
        !infoSubtitle ||
        !infoIP ||
        !infoUser ||
        !infoImage ||
        !infoCreated ||
        !infoClose) {
        return;
    }
    const formEl = form;
    const inputEl = input;
    const usernameInputEl = usernameInput;
    const passwordInputEl = passwordInput;
    const passwordConfirmInputEl = passwordConfirmInput;
    const cpuSelectEl = cpuSelect;
    const memorySelectEl = memorySelect;
    const baseImageSelectEl = baseImageSelect;
    const createButtonEl = createButton;
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
    const infoModalEl = infoModal;
    const infoBackdropEl = infoBackdrop;
    const infoSubtitleEl = infoSubtitle;
    const infoIPEl = infoIP;
    const infoUserEl = infoUser;
    const infoImageEl = infoImage;
    const infoCreatedEl = infoCreated;
    const infoCloseEl = infoClose;
    let terminalSocket = null;
    let terminalInstance = null;
    let terminalFitAddon = null;
    let terminalInputDisposable = null;
    let terminalClosing = false;
    let terminalResizeFrame = 0;
    let defaultUsername = "";
    let usernameInitialized = false;
    let baseImages = [];
    const terminalResizeObserver = new ResizeObserver(() => {
        requestTerminalFit();
    });
    terminalResizeObserver.observe(terminalDialogEl);
    terminalResizeObserver.observe(terminalSurfaceEl);
    function isFullscreenTarget(element) {
        return document.fullscreenElement === element;
    }
    async function toggleFullscreen(element) {
        try {
            if (isFullscreenTarget(element)) {
                await document.exitFullscreen();
                return;
            }
            await element.requestFullscreen();
        }
        catch (error) {
            console.error("fullscreen toggle failed", error);
        }
    }
    function exitFullscreenIfNeeded(element) {
        if (isFullscreenTarget(element)) {
            void document.exitFullscreen();
        }
    }
    function requestTerminalFit() {
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
            }
            catch (error) {
                console.error("terminal fit failed", error);
            }
            if (terminalInstance) {
                terminalInstance.focus();
            }
        });
    }
    function renderAction() {
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
    function renderTerminal() {
        terminalModalEl.hidden = !state.terminal.open;
        terminalModalEl.setAttribute("aria-hidden", state.terminal.open ? "false" : "true");
        terminalSubtitleEl.textContent = state.terminal.vmDisplayName || state.terminal.vmName;
        terminalStatusEl.textContent = state.terminal.status;
        if (isFullscreenTarget(terminalDialogEl)) {
            setIconLabel(terminalFullscreenEl, "bi-arrows-angle-contract", "Exit Fullscreen");
        }
        else {
            setIconLabel(terminalFullscreenEl, "bi-arrows-fullscreen", "Fullscreen");
        }
        if (state.terminal.error) {
            terminalErrorEl.textContent = state.terminal.error;
            terminalErrorEl.classList.remove("d-none");
        }
        else {
            terminalErrorEl.textContent = "";
            terminalErrorEl.classList.add("d-none");
        }
        if (!state.terminal.open) {
            terminalSurfaceEl.innerHTML = "";
        }
    }
    function renderVNC() {
        vncModalEl.hidden = !state.vnc.open;
        vncModalEl.setAttribute("aria-hidden", state.vnc.open ? "false" : "true");
        vncSubtitleEl.textContent = state.vnc.vmDisplayName || state.vnc.vmName;
        if (state.vnc.open) {
            if (vncFrameEl.getAttribute("src") !== state.vnc.src) {
                vncFrameEl.setAttribute("src", state.vnc.src);
            }
        }
        else {
            vncFrameEl.removeAttribute("src");
        }
    }
    function renderCreate() {
        createModalEl.hidden = !state.create.open;
        createModalEl.setAttribute("aria-hidden", state.create.open ? "false" : "true");
        if (state.create.error) {
            createErrorEl.textContent = state.create.error;
            createErrorEl.classList.remove("d-none");
        }
        else {
            createErrorEl.textContent = "";
            createErrorEl.classList.add("d-none");
        }
    }
    function setCreateError(message) {
        state.create.error = message;
        renderCreate();
    }
    function openCreate() {
        closeTerminal();
        closeVNC();
        state.create.open = true;
        state.create.error = "";
        renderCreate();
        inputEl.focus();
    }
    function closeCreate() {
        state.create.open = false;
        state.create.error = "";
        renderCreate();
    }
    function teardownTerminalRuntime() {
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
            }
            catch (_a) {
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
    function closeVNC() {
        state.vnc.open = false;
        state.vnc.vmName = "";
        state.vnc.vmDisplayName = "";
        state.vnc.src = "";
        renderVNC();
    }
    function renderInfo() {
        infoModalEl.hidden = !state.info.open;
        infoModalEl.setAttribute("aria-hidden", state.info.open ? "false" : "true");
        infoSubtitleEl.textContent = state.info.vmDisplayName || state.info.vmName;
        infoIPEl.textContent = state.info.ip || "n/a";
        infoUserEl.textContent = state.info.user || "n/a";
        infoImageEl.textContent = state.info.baseImage || "n/a";
        infoCreatedEl.textContent = formatCreatedAt(state.info.created);
    }
    function openInfo(vm) {
        const ipValue = (vm.ip || "").trim();
        state.info.open = true;
        state.info.vmName = vm.name;
        state.info.vmDisplayName = vm.displayName || vm.name;
        state.info.ip = ipValue.toLowerCase() === "n/a" ? "" : ipValue;
        state.info.user = (vm.user || "").trim();
        state.info.baseImage = (vm.baseImage || "").trim();
        state.info.created = (vm.createdAt || "").trim();
        renderInfo();
    }
    function closeInfo() {
        state.info.open = false;
        state.info.vmName = "";
        state.info.vmDisplayName = "";
        state.info.ip = "";
        state.info.user = "";
        state.info.baseImage = "";
        state.info.created = "";
        renderInfo();
    }
    function closeTerminal() {
        exitFullscreenIfNeeded(terminalDialogEl);
        teardownTerminalRuntime();
        state.terminal.open = false;
        state.terminal.vmName = "";
        state.terminal.vmDisplayName = "";
        state.terminal.status = "";
        state.terminal.error = "";
        renderTerminal();
    }
    function handleTerminalMessage(data) {
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
    function openTerminal(vm) {
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
                background: "#020617",
                foreground: "#e2e8f0",
                cursor: "#38bdf8",
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
        socket.onmessage = (event) => {
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
    function openVNC(vm) {
        closeTerminal();
        state.vnc.open = true;
        state.vnc.vmName = vm.name;
        state.vnc.vmDisplayName = vm.displayName || vm.name;
        state.vnc.src = vncFrameURL(vm.name);
        renderVNC();
    }
    function renderVMList() {
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
        const wrap = document.createElement("div");
        wrap.className = "table-responsive";
        const table = document.createElement("table");
        table.className = "table table-dark table-hover align-middle mb-0";
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        const columns = [
            "Name",
            "Connect",
            "State",
            "Memory (GB)",
            "vCPU",
            "Disk",
            "Actions",
        ];
        for (const label of columns) {
            const th = document.createElement("th");
            th.scope = "col";
            th.textContent = label;
            headRow.appendChild(th);
        }
        thead.appendChild(headRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        for (const vm of state.vms) {
            const row = document.createElement("tr");
            const rawName = vm.name || "";
            const displayName = vm.displayName || rawName;
            const normalizedState = (vm.state || "").trim().toLowerCase();
            const ipValue = (vm.ip || "").trim();
            const hasIP = ipValue !== "" && ipValue.toLowerCase() !== "n/a";
            const ttyReady = Boolean(vm.ttyReady);
            const vncReady = Boolean(vm.vncReady);
            const hasName = rawName.trim() !== "";
            const isActive = isActiveState(normalizedState);
            const nameCell = document.createElement("td");
            nameCell.className = "fw-semibold";
            nameCell.textContent = displayName || "n/a";
            row.appendChild(nameCell);
            const connectCell = document.createElement("td");
            connectCell.className = "align-top";
            if (hasName) {
                const connectStack = document.createElement("div");
                connectStack.className = "d-flex flex-column gap-2";
                const connectActions = document.createElement("div");
                connectActions.className = "d-flex flex-wrap gap-2";
                if (vm.rdpConnect && displayName.trim() !== "") {
                    if (hasIP) {
                        const connectButton = document.createElement("a");
                        connectButton.className = "btn btn-sm btn-success";
                        connectButton.href = vm.rdpConnect;
                        setIconLabel(connectButton, "bi-display", "RDP");
                        connectButton.setAttribute("download", vm.rdpFilename || state.filename);
                        connectActions.appendChild(connectButton);
                    }
                    else {
                        const offlineBadge = document.createElement("span");
                        offlineBadge.className = "btn btn-sm btn-outline-danger disabled";
                        setIconLabel(offlineBadge, "bi-slash-circle", "Offline");
                        offlineBadge.setAttribute("aria-disabled", "true");
                        connectActions.appendChild(offlineBadge);
                    }
                }
                const terminalButton = document.createElement("button");
                terminalButton.type = "button";
                terminalButton.className = "btn btn-sm btn-outline-info";
                setIconLabel(terminalButton, "bi-terminal", "Terminal");
                terminalButton.disabled = state.busy || !ttyReady || !isActive;
                terminalButton.addEventListener("click", () => {
                    openTerminal(vm);
                });
                connectActions.appendChild(terminalButton);
                const vncButton = document.createElement("button");
                vncButton.type = "button";
                vncButton.className = "btn btn-sm btn-outline-primary";
                setIconLabel(vncButton, "bi-window-desktop", "NoVNC");
                vncButton.disabled = state.busy || !vncReady || !isActive;
                vncButton.addEventListener("click", () => {
                    openVNC(vm);
                });
                connectActions.appendChild(vncButton);
                const infoButton = document.createElement("button");
                infoButton.type = "button";
                infoButton.className = "btn btn-sm btn-outline-secondary";
                setIconLabel(infoButton, "bi-info-circle", "Info");
                infoButton.addEventListener("click", () => {
                    openInfo(vm);
                });
                connectActions.appendChild(infoButton);
                connectStack.appendChild(connectActions);
                if (ttyReady && !isActive) {
                    const note = document.createElement("div");
                    note.className = "text-body-secondary small";
                    note.textContent = "Start VM to open terminal.";
                    connectStack.appendChild(note);
                }
                if (!ttyReady) {
                    const note = document.createElement("div");
                    note.className = "text-body-secondary small";
                    note.textContent = "TTY available only for newly created VMs.";
                    connectStack.appendChild(note);
                }
                if (vncReady && !isActive) {
                    const note = document.createElement("div");
                    note.className = "text-body-secondary small";
                    note.textContent = "Start VM to open NoVNC.";
                    connectStack.appendChild(note);
                }
                if (!vncReady) {
                    const note = document.createElement("div");
                    note.className = "text-body-secondary small";
                    note.textContent = "NoVNC available only for newly created VMs.";
                    connectStack.appendChild(note);
                }
                connectCell.appendChild(connectStack);
            }
            else {
                connectCell.textContent = "n/a";
                connectCell.classList.add("text-body-secondary");
            }
            row.appendChild(connectCell);
            const stateCell = document.createElement("td");
            const stateBadge = document.createElement("span");
            let stateClass = "text-bg-secondary";
            if (normalizedState === "running") {
                stateClass = "text-bg-success";
            }
            else if (normalizedState === "paused") {
                stateClass = "text-bg-warning";
            }
            else if (normalizedState === "suspended") {
                stateClass = "text-bg-danger";
            }
            const stateText = normalizedState ? (vm.state || "").trim() : "n/a";
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
            if (hasName && !isActive) {
                const resourceRow = document.createElement("div");
                resourceRow.className = "d-flex flex-nowrap gap-2 align-items-center";
                const vcpuSelect = buildSelect(VCPU_OPTIONS, vm.vcpu || DEFAULT_VCPU, (value) => `${value} vCPU`);
                vcpuSelect.className = "form-select form-select-sm vm-resource-select w-auto";
                vcpuSelect.setAttribute("aria-label", "vCPU");
                vcpuSelect.disabled = state.busy;
                const memorySelect = buildSelect(MEMORY_OPTIONS, vm.memoryMiB || DEFAULT_MEMORY_MIB, (value) => formatMemoryGB(value));
                memorySelect.className = "form-select form-select-sm vm-resource-select w-auto";
                memorySelect.setAttribute("aria-label", "Memory");
                memorySelect.disabled = state.busy;
                const applyButton = document.createElement("button");
                applyButton.type = "button";
                applyButton.className = "btn btn-sm btn-outline-primary w-auto";
                setIconLabel(applyButton, "bi-check-lg", "Apply");
                applyButton.disabled = state.busy;
                applyButton.addEventListener("click", () => {
                    void updateVMResources(rawName, vcpuSelect.value, memorySelect.value);
                });
                resourceRow.appendChild(vcpuSelect);
                resourceRow.appendChild(memorySelect);
                resourceRow.appendChild(applyButton);
                actionStack.appendChild(resourceRow);
            }
            if (hasName && isActive) {
                const note = document.createElement("div");
                note.className = "text-body-secondary small";
                note.textContent = "Stop VM to edit resources.";
                actionStack.appendChild(note);
            }
            actionCell.appendChild(actionStack);
            row.appendChild(actionCell);
            tbody.appendChild(row);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        listAreaEl.appendChild(wrap);
    }
    // updateCreateAvailability keeps the base image picker and the create button
    // disabled while busy or when the gateway offers no base images to clone.
    function updateCreateAvailability() {
        const noImages = baseImages.length === 0;
        baseImageSelectEl.disabled = state.busy || noImages;
        createButtonEl.disabled = state.busy || noImages;
    }
    // renderBaseImageOptions rebuilds the picker from the latest list, preserving
    // a still-valid selection. An empty list shows a disabled placeholder so the
    // required field blocks submission.
    function renderBaseImageOptions() {
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
    function setBusy(isBusy) {
        state.busy = isBusy;
        inputEl.disabled = isBusy;
        usernameInputEl.disabled = isBusy;
        passwordInputEl.disabled = isBusy;
        passwordConfirmInputEl.disabled = isBusy;
        cpuSelectEl.disabled = isBusy;
        memorySelectEl.disabled = isBusy;
        updateCreateAvailability();
        renderVMList();
    }
    function setActionError(message) {
        state.actionError = message;
        state.actionMessage = "";
        renderAction();
    }
    function setActionMessage(message) {
        state.actionMessage = message;
        state.actionError = "";
        renderAction();
    }
    function clearAction() {
        state.actionError = "";
        state.actionMessage = "";
        renderAction();
    }
    function confirmRemoval(name) {
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
    function applyInitialMessage() {
        const params = new URLSearchParams(window.location.search);
        if (params.has("removed")) {
            setActionMessage("VM removed.");
            params.delete("removed");
        }
        else if (params.has("created")) {
            setActionMessage("VM creation started.");
            params.delete("created");
        }
        if (params.toString() !== window.location.search.replace(/^\?/, "")) {
            const query = params.toString();
            const next = query ? `${window.location.pathname}?${query}` : window.location.pathname;
            window.history.replaceState({}, "", next);
        }
    }
    function redirectToLogin() {
        state.vms = [];
        state.vmError = "";
        state.loading = true;
        clearAction();
        closeTerminal();
        closeVNC();
        renderVMList();
        window.location.replace(LOGIN_PATH);
        return null;
    }
    function responseRequiresLogin(response) {
        if (response.status === 401) {
            return true;
        }
        try {
            const finalUrl = new URL(response.url, window.location.origin);
            return finalUrl.pathname === LOGIN_PATH;
        }
        catch (_a) {
            return false;
        }
    }
    async function requestJSON(url, init = {}) {
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        let response;
        try {
            response = await fetch(url, Object.assign(Object.assign({}, init), { cache: "no-store", headers, credentials: "same-origin" }));
        }
        catch (_a) {
            return { ok: false, error: SESSION_CHECK_ERROR };
        }
        if (responseRequiresLogin(response)) {
            return redirectToLogin();
        }
        let payload = null;
        try {
            payload = await response.json();
        }
        catch (_b) {
            payload = null;
        }
        if (!response.ok) {
            const errorMessage = payload && typeof payload.error === "string"
                ? payload.error
                : "Request failed.";
            return { ok: false, error: errorMessage };
        }
        return { ok: true, data: payload };
    }
    async function loadVMs(options = {}) {
        var _a;
        if (loadInFlight) {
            return;
        }
        loadInFlight = true;
        const showLoading = (_a = options.showLoading) !== null && _a !== void 0 ? _a : state.vms.length === 0;
        if (showLoading) {
            state.loading = true;
            state.vmError = "";
            renderVMList();
        }
        try {
            const result = await requestJSON("/api/dashboard/data");
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                state.vms = [];
                state.vmError = result.error || DEFAULT_VM_ERROR;
                return;
            }
            state.vms = result.data.vms || [];
            baseImages = result.data.baseImages || [];
            renderBaseImageOptions();
            if (result.data.filename) {
                state.filename = result.data.filename;
            }
            if (typeof result.data.username === "string" && result.data.username !== "") {
                defaultUsername = result.data.username;
                usernameInputEl.placeholder = defaultUsername;
                // Prefill the default once so the field shows the logged-in user
                // without clobbering anything the user has already typed.
                if (!usernameInitialized && document.activeElement !== usernameInputEl) {
                    usernameInputEl.value = defaultUsername;
                    usernameInitialized = true;
                }
            }
            if (result.data.error) {
                state.vmError = result.data.error;
            }
            else {
                state.vmError = "";
            }
        }
        finally {
            state.loading = false;
            renderVMList();
            loadInFlight = false;
        }
    }
    async function createVM(name, username, password, passwordConfirm, vcpu, memoryMiB, baseImage) {
        if (state.busy) {
            return;
        }
        clearAction();
        setCreateError("");
        setBusy(true);
        try {
            const body = new URLSearchParams({
                vm_name: name,
                vm_username: username,
                vm_password: password,
                vm_password_confirm: passwordConfirm,
                vm_vcpu: vcpu,
                vm_memory_mib: memoryMiB,
                vm_base_image: baseImage,
            });
            const result = await requestJSON("/api/dashboard", {
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
                setCreateError(result.error || "Failed to create VM.");
                return;
            }
            if (!result.data.ok) {
                setCreateError(result.data.error || "Failed to create VM.");
                return;
            }
            setActionMessage(result.data.message || "VM creation started.");
            inputEl.value = "";
            usernameInputEl.value = defaultUsername;
            passwordInputEl.value = "";
            passwordConfirmInputEl.value = "";
            passwordConfirmInputEl.setCustomValidity("");
            cpuSelectEl.value = DEFAULT_VCPU;
            memorySelectEl.value = DEFAULT_MEMORY_MIB;
            closeCreate();
            await loadVMs();
        }
        finally {
            setBusy(false);
        }
    }
    async function actionVM(name, url, successMessage, failureMessage) {
        if (state.busy) {
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({ vm_name: name });
            const result = await requestJSON(url, {
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
            await loadVMs();
        }
        finally {
            setBusy(false);
        }
    }
    async function updateVMResources(name, vcpu, memoryMiB) {
        if (state.busy) {
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({
                vm_name: name,
                vm_vcpu: vcpu,
                vm_memory_mib: memoryMiB,
            });
            const result = await requestJSON("/api/dashboard/resources", {
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
                setActionError(result.error || "Failed to update VM resources.");
                return;
            }
            if (!result.data.ok) {
                setActionError(result.data.error || "Failed to update VM resources.");
                return;
            }
            setActionMessage(result.data.message || "VM resources updated.");
            await loadVMs();
        }
        finally {
            setBusy(false);
        }
    }
    async function removeVM(name) {
        await actionVM(name, "/api/dashboard/remove", "VM removed.", "Failed to remove VM.");
    }
    async function startVM(name) {
        await actionVM(name, "/api/dashboard/start", "VM start requested.", "Failed to start VM.");
    }
    async function restartVM(name) {
        await actionVM(name, "/api/dashboard/restart", "VM restart requested.", "Failed to restart VM.");
    }
    async function shutdownVM(name) {
        await actionVM(name, "/api/dashboard/shutdown", "VM stop requested.", "Failed to stop VM.");
    }
    // Keep the native "passwords must match" message in sync as the user types,
    // so the confirm field reflects the current match state on the next submit.
    const syncPasswordMatch = () => {
        passwordConfirmInputEl.setCustomValidity(passwordInputEl.value === passwordConfirmInputEl.value ? "" : "Passwords do not match.");
    };
    passwordInputEl.addEventListener("input", syncPasswordMatch);
    passwordConfirmInputEl.addEventListener("input", syncPasswordMatch);
    formEl.addEventListener("submit", (event) => {
        event.preventDefault();
        syncPasswordMatch();
        if (!formEl.reportValidity()) {
            return;
        }
        void createVM(inputEl.value.trim(), usernameInputEl.value.trim(), passwordInputEl.value, passwordConfirmInputEl.value, cpuSelectEl.value, memorySelectEl.value, baseImageSelectEl.value);
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
    document.addEventListener("keydown", (event) => {
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
    updateCreateAvailability();
    void loadVMs();
    const refreshHandle = window.setInterval(() => {
        if (document.hidden || state.busy) {
            return;
        }
        void loadVMs({ showLoading: false });
    }, AUTO_REFRESH_INTERVAL_MS);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) {
            void loadVMs({ showLoading: false });
        }
    });
    window.addEventListener("focus", () => {
        if (!state.busy) {
            void loadVMs({ showLoading: false });
        }
    });
    window.addEventListener("pageshow", () => {
        void loadVMs({ showLoading: false });
    });
    window.addEventListener("beforeunload", () => {
        window.clearInterval(refreshHandle);
        terminalResizeObserver.disconnect();
        teardownTerminalRuntime();
        closeVNC();
    });
}
bootstrap();
