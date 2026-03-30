// Source for the dashboard UI. Run "tsc -p tsconfig.json" to update static/dashboard.js.

const DEFAULT_VM_ERROR = "Unable to load virtual machines right now.";
const AUTO_REFRESH_INTERVAL_MS = 10000;
const DEFAULT_VCPU = "4";
const DEFAULT_MEMORY_MIB = "4096";
const VCPU_OPTIONS = ["1", "2", "4", "8"];
const MEMORY_OPTIONS = ["4096", "8192", "16384", "32768"];

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
    rdpConnect: string;
    ip: string;
    state: string;
    memoryMiB: number;
    vcpu: number;
    volumeGB: number;
    ttyReady: boolean;
};

type DashboardDataResponse = {
    filename?: string;
    vms?: DashboardVM[];
    error?: string;
};

type DashboardActionResponse = {
    ok?: boolean;
    message?: string;
    error?: string;
};

type DashboardTerminalState = {
    open: boolean;
    vmName: string;
    vmDisplayName: string;
    status: string;
    error: string;
};

type DashboardState = {
    vms: DashboardVM[];
    filename: string;
    vmError: string;
    actionMessage: string;
    actionError: string;
    loading: boolean;
    busy: boolean;
    terminal: DashboardTerminalState;
};

type RequestResult<T> = {
    ok: boolean;
    data?: T;
    error?: string;
};

type LoadVMOptions = {
    showLoading?: boolean;
};

const state: DashboardState = {
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
};

let loadInFlight = false;

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

function buildSelect<T extends string | number>(
    options: readonly T[],
    selectedValue: string | number,
    labelFn: (value: T) => string,
): HTMLSelectElement {
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

function terminalWebSocketURL(name: string): string {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}/api/dashboard/console/${encodeURIComponent(name)}/ws`;
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
          <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-4">
            <div>
              <h1 class="h4 mb-1">Available DevBoxes</h1>
              <p class="text-body-secondary mb-0">Live inventory.</p>
            </div>
            <a class="btn btn-outline-secondary btn-sm" href="/logout">Logout</a>
          </div>
          <form class="row g-3 align-items-end" id="create-form">
            <div class="col-12 col-md-6 col-lg-5">
              <label class="form-label" for="vm-name">New DevBox Name</label>
              <input class="form-control" id="vm-name" name="vm_name" autocomplete="off" pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" maxlength="63" title="Lowercase letters, numbers, and hyphens only. Must start/end with a letter or number. Max 63 characters." autocapitalize="none" spellcheck="false" required>
            </div>
            <div class="col-6 col-md-3 col-lg-2">
              <label class="form-label" for="vm-cpu">vCPU</label>
              <select class="form-select" id="vm-cpu" name="vm_vcpu" required>
                <option value="1">1 vCPU</option>
                <option value="2">2 vCPU</option>
                <option value="4" selected>4 vCPU</option>
                <option value="8">8 vCPU</option>
              </select>
            </div>
            <div class="col-6 col-md-3 col-lg-2">
              <label class="form-label" for="vm-memory">Memory</label>
              <select class="form-select" id="vm-memory" name="vm_memory_mib" required>
                <option value="4096" selected>4 GB</option>
                <option value="8192">8 GB</option>
                <option value="16384">16 GB</option>
                <option value="32768">32 GB</option>
              </select>
            </div>
            <div class="col-12 col-md-12 col-lg-3 d-grid">
              <button class="btn btn-outline-primary" id="create-button" type="submit">Create DevBox</button>
            </div>
          </form>
          <div id="action-area" class="mt-3" aria-live="polite"></div>
          <div id="vm-list" class="mt-3"></div>
        </div>
      </div>
    </main>
    <div id="terminal-modal" class="terminal-modal" hidden aria-hidden="true">
      <div class="terminal-modal__backdrop" id="terminal-backdrop"></div>
      <div class="terminal-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="terminal-title">
        <div class="terminal-modal__body">
          <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h2 class="h5 mb-1" id="terminal-title">Serial Terminal</h2>
              <p class="text-body-secondary mb-0" id="terminal-subtitle"></p>
            </div>
            <button class="btn btn-outline-secondary btn-sm" id="terminal-close" type="button">Close</button>
          </div>
          <div class="terminal-hint mb-2" id="terminal-status" aria-live="polite"></div>
          <div class="alert alert-danger mb-3 d-none" id="terminal-error" role="alert"></div>
          <div class="terminal-modal__surface" id="terminal-surface"></div>
        </div>
      </div>
    </div>
  `;

    const form = root.querySelector<HTMLFormElement>("#create-form");
    const input = root.querySelector<HTMLInputElement>("#vm-name");
    const cpuSelect = root.querySelector<HTMLSelectElement>("#vm-cpu");
    const memorySelect = root.querySelector<HTMLSelectElement>("#vm-memory");
    const createButton = root.querySelector<HTMLButtonElement>("#create-button");
    const actionArea = root.querySelector<HTMLDivElement>("#action-area");
    const listArea = root.querySelector<HTMLDivElement>("#vm-list");
    const terminalModal = root.querySelector<HTMLDivElement>("#terminal-modal");
    const terminalBackdrop = root.querySelector<HTMLDivElement>("#terminal-backdrop");
    const terminalSubtitle = root.querySelector<HTMLParagraphElement>("#terminal-subtitle");
    const terminalStatus = root.querySelector<HTMLDivElement>("#terminal-status");
    const terminalError = root.querySelector<HTMLDivElement>("#terminal-error");
    const terminalSurface = root.querySelector<HTMLDivElement>("#terminal-surface");
    const terminalClose = root.querySelector<HTMLButtonElement>("#terminal-close");

    if (
        !form ||
        !input ||
        !cpuSelect ||
        !memorySelect ||
        !createButton ||
        !actionArea ||
        !listArea ||
        !terminalModal ||
        !terminalBackdrop ||
        !terminalSubtitle ||
        !terminalStatus ||
        !terminalError ||
        !terminalSurface ||
        !terminalClose
    ) {
        return;
    }

    const formEl = form;
    const inputEl = input;
    const cpuSelectEl = cpuSelect;
    const memorySelectEl = memorySelect;
    const createButtonEl = createButton;
    const actionAreaEl = actionArea;
    const listAreaEl = listArea;
    const terminalModalEl = terminalModal;
    const terminalBackdropEl = terminalBackdrop;
    const terminalSubtitleEl = terminalSubtitle;
    const terminalStatusEl = terminalStatus;
    const terminalErrorEl = terminalError;
    const terminalSurfaceEl = terminalSurface;
    const terminalCloseEl = terminalClose;

    let terminalSocket: WebSocket | null = null;
    let terminalInstance: XTermTerminal | null = null;
    let terminalFitAddon: XTermFitAddon | null = null;
    let terminalInputDisposable: Disposable | null = null;
    let terminalClosing = false;

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

    function teardownTerminalRuntime(): void {
        terminalClosing = true;
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

    function closeTerminal(): void {
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
        terminalFitAddon.fit();
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
            window.requestAnimationFrame(() => {
                if (terminalFitAddon) {
                    terminalFitAddon.fit();
                }
                if (terminalInstance) {
                    terminalInstance.focus();
                }
            });
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

        const wrap = document.createElement("div");
        wrap.className = "table-responsive";
        const table = document.createElement("table");
        table.className = "table table-dark table-hover align-middle mb-0";
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        const columns = [
            "Name",
            "Connect",
            "IP Address",
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

            const nameCell = document.createElement("td");
            nameCell.className = "fw-semibold";
            nameCell.textContent = displayName || "n/a";
            row.appendChild(nameCell);

            const connectCell = document.createElement("td");
            if (vm.rdpConnect && displayName.trim() !== "") {
                if (hasIP) {
                    const connectButton = document.createElement("a");
                    connectButton.className = "btn btn-sm btn-success";
                    connectButton.href = vm.rdpConnect;
                    connectButton.textContent = "Connect";
                    connectButton.setAttribute("download", state.filename);
                    connectCell.appendChild(connectButton);
                } else {
                    const offlineBadge = document.createElement("span");
                    offlineBadge.className = "btn btn-sm btn-outline-danger disabled";
                    offlineBadge.textContent = "Offline";
                    offlineBadge.setAttribute("aria-disabled", "true");
                    connectCell.appendChild(offlineBadge);
                }
            } else {
                connectCell.textContent = "n/a";
                connectCell.className = "text-body-secondary";
            }
            row.appendChild(connectCell);

            const ipCell = document.createElement("td");
            ipCell.textContent = hasIP ? ipValue : "n/a";
            row.appendChild(ipCell);

            const stateCell = document.createElement("td");
            const stateBadge = document.createElement("span");
            let stateClass = "text-bg-secondary";
            if (normalizedState === "running") {
                stateClass = "text-bg-success";
            } else if (normalizedState === "paused") {
                stateClass = "text-bg-warning";
            } else if (normalizedState === "suspended") {
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

            const hasName = rawName.trim() !== "";
            const isActive = isActiveState(normalizedState);

            const actionCell = document.createElement("td");
            actionCell.className = "align-top";
            const actionStack = document.createElement("div");
            actionStack.className = "d-flex flex-column gap-2";

            const actions = document.createElement("div");
            actions.className = "d-flex flex-wrap gap-2";

            const terminalButton = document.createElement("button");
            terminalButton.type = "button";
            terminalButton.className = "btn btn-sm btn-outline-info";
            terminalButton.textContent = "Terminal";
            terminalButton.disabled = state.busy || !hasName || !ttyReady || !isActive;
            terminalButton.addEventListener("click", () => {
                openTerminal(vm);
            });
            actions.appendChild(terminalButton);

            const startButton = document.createElement("button");
            startButton.type = "button";
            startButton.className = "btn btn-sm btn-outline-success";
            startButton.textContent = "Start";
            startButton.disabled = state.busy || !hasName || isActive;
            startButton.addEventListener("click", () => {
                void startVM(rawName);
            });
            actions.appendChild(startButton);

            const restartButton = document.createElement("button");
            restartButton.type = "button";
            restartButton.className = "btn btn-sm btn-outline-secondary";
            restartButton.textContent = "Restart";
            restartButton.disabled = state.busy || !hasName || !isActive;
            restartButton.addEventListener("click", () => {
                void restartVM(rawName);
            });
            actions.appendChild(restartButton);

            const shutdownButton = document.createElement("button");
            shutdownButton.type = "button";
            shutdownButton.className = "btn btn-sm btn-outline-warning";
            shutdownButton.textContent = "Stop";
            shutdownButton.disabled = state.busy || !hasName || !isActive;
            shutdownButton.addEventListener("click", () => {
                void shutdownVM(rawName);
            });
            actions.appendChild(shutdownButton);

            const removeButton = document.createElement("button");
            removeButton.type = "button";
            removeButton.className = "btn btn-sm btn-outline-danger";
            removeButton.textContent = "Remove";
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
                const memorySelect = buildSelect(
                    MEMORY_OPTIONS,
                    vm.memoryMiB || DEFAULT_MEMORY_MIB,
                    (value) => formatMemoryGB(value),
                );
                memorySelect.className = "form-select form-select-sm vm-resource-select w-auto";
                memorySelect.setAttribute("aria-label", "Memory");
                memorySelect.disabled = state.busy;
                const applyButton = document.createElement("button");
                applyButton.type = "button";
                applyButton.className = "btn btn-sm btn-outline-primary w-auto";
                applyButton.textContent = "Apply";
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

            if (hasName && ttyReady && !isActive) {
                const note = document.createElement("div");
                note.className = "text-body-secondary small";
                note.textContent = "Start VM to open terminal.";
                actionStack.appendChild(note);
            }

            if (hasName && !ttyReady) {
                const note = document.createElement("div");
                note.className = "text-body-secondary small";
                note.textContent = "TTY available only for newly created VMs.";
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

    function setBusy(isBusy: boolean): void {
        state.busy = isBusy;
        inputEl.disabled = isBusy;
        cpuSelectEl.disabled = isBusy;
        memorySelectEl.disabled = isBusy;
        createButtonEl.disabled = isBusy;
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

    async function requestJSON<T>(url: string, init: RequestInit = {}): Promise<RequestResult<T> | null> {
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        const response = await fetch(url, {
            ...init,
            headers,
            credentials: "same-origin",
        });
        if (response.redirected) {
            const redirectedUrl = new URL(response.url);
            if (redirectedUrl.pathname === "/login") {
                window.location.assign("/login");
                return null;
            }
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

    async function loadVMs(options: LoadVMOptions = {}): Promise<void> {
        if (loadInFlight) {
            return;
        }
        loadInFlight = true;
        const showLoading = options.showLoading ?? state.vms.length === 0;
        if (showLoading) {
            state.loading = true;
            state.vmError = "";
            renderVMList();
        }
        try {
            const result = await requestJSON<DashboardDataResponse>("/api/dashboard/data");
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                state.vmError = result.error || DEFAULT_VM_ERROR;
                return;
            }
            state.vms = result.data.vms || [];
            if (result.data.filename) {
                state.filename = result.data.filename;
            }
            if (result.data.error) {
                state.vmError = result.data.error;
            } else {
                state.vmError = "";
            }
        } finally {
            state.loading = false;
            renderVMList();
            loadInFlight = false;
        }
    }

    async function createVM(name: string, vcpu: string, memoryMiB: string): Promise<void> {
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
            const result = await requestJSON<DashboardActionResponse>("/api/dashboard", {
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
                setActionError(result.error || "Failed to create VM.");
                return;
            }
            if (!result.data.ok) {
                setActionError(result.data.error || "Failed to create VM.");
                return;
            }
            setActionMessage(result.data.message || "VM creation started.");
            inputEl.value = "";
            cpuSelectEl.value = DEFAULT_VCPU;
            memorySelectEl.value = DEFAULT_MEMORY_MIB;
            await loadVMs();
        } finally {
            setBusy(false);
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
            await loadVMs();
        } finally {
            setBusy(false);
        }
    }

    async function updateVMResources(name: string, vcpu: string, memoryMiB: string): Promise<void> {
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
            const result = await requestJSON<DashboardActionResponse>("/api/dashboard/resources", {
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

    formEl.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!formEl.reportValidity()) {
            return;
        }
        void createVM(inputEl.value.trim(), cpuSelectEl.value, memorySelectEl.value);
    });

    terminalBackdropEl.addEventListener("click", () => {
        closeTerminal();
    });

    terminalCloseEl.addEventListener("click", () => {
        closeTerminal();
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && state.terminal.open) {
            closeTerminal();
        }
    });

    window.addEventListener("resize", () => {
        if (state.terminal.open && terminalFitAddon) {
            terminalFitAddon.fit();
        }
    });

    applyInitialMessage();
    renderAction();
    renderVMList();
    renderTerminal();
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

    window.addEventListener("beforeunload", () => {
        window.clearInterval(refreshHandle);
        teardownTerminalRuntime();
    });
}

bootstrap();
