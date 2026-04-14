import { Terminal, ITerminalOptions } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebglAddon } from '@xterm/addon-webgl';
import { CanvasAddon } from '@xterm/addon-canvas';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import '@xterm/xterm/css/xterm.css';
import * as Zmodem from 'zmodem.js/src/zmodem_browser';
import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';

// ── ttyd protocol constants ──────────────────────────────────────────────────

/** Client → Server */
const CMD_INPUT = '0';
const CMD_RESIZE = '1';
const CMD_PAUSE = '2';
const CMD_RESUME = '3';

/** Server → Client */
const SRV_OUTPUT = 0x30; // '0'
const SRV_SET_TITLE = 0x31; // '1'
const SRV_SET_PREFS = 0x32; // '2'

/** Noise transport */
const NOISE_CLIENT_HELLO = 0x90;
const NOISE_SERVER_HELLO = 0x91;
const NOISE_DATA = 0x92;
const NOISE_PROTOCOL = 'Noise_NN_25519_ChaChaPoly_SHA256';

// ── helpers ──────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const dec = new TextDecoder();

function buildUrl(path: string): string {
    const loc = window.location;
    const base = loc.pathname.replace(/\/+$/, '');
    return `${loc.protocol}//${loc.host}${base}${path}${loc.search}`;
}

function buildWsUrl(): string {
    const loc = window.location;
    const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
    const base = loc.pathname.replace(/\/+$/, '');
    return `${proto}//${loc.host}${base}/ws${loc.search}`;
}

function noiseProtocolState(): Uint8Array {
    const proto = enc.encode(NOISE_PROTOCOL);
    if (proto.length <= 32) {
        const out = new Uint8Array(32);
        out.set(proto);
        return out;
    }
    return sha256(proto);
}

function noiseMixHash(h: Uint8Array, data: Uint8Array): Uint8Array {
    return sha256(concatBytes(h, data));
}

function noiseMixKey(ck: Uint8Array, ikm: Uint8Array): { ck: Uint8Array; tempKey: Uint8Array } {
    const out = hkdf(sha256, ikm, ck, new Uint8Array(), 64);
    return {
        ck: out.slice(0, 32),
        tempKey: out.slice(32, 64),
    };
}

function noiseSplit(ck: Uint8Array): { k1: Uint8Array; k2: Uint8Array } {
    const out = hkdf(sha256, new Uint8Array(), ck, new Uint8Array(), 64);
    return { k1: out.slice(0, 32), k2: out.slice(32, 64) };
}

const NOISE_NONCE_MAX = (1n << 64n) - 1n;

function noiseNonce96(n: bigint): Uint8Array {
    const out = new Uint8Array(12);
    for (let i = 0; i < 8; i++) {
        out[4 + i] = Number((n >> BigInt(8 * i)) & 0xffn);
    }
    return out;
}

function encryptWithAd(key: Uint8Array, nonce: bigint, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    return chacha20poly1305(key, noiseNonce96(nonce), ad).encrypt(plaintext);
}

function decryptWithAd(key: Uint8Array, nonce: bigint, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return chacha20poly1305(key, noiseNonce96(nonce), ad).decrypt(ciphertext);
}

class NoiseTransport {
    private sendNonce = 0n;
    private recvNonce = 0n;

    constructor(private sendKey: Uint8Array, private recvKey: Uint8Array) {}

    encryptFrame(plain: Uint8Array): Uint8Array {
        if (this.sendNonce >= NOISE_NONCE_MAX) {
            throw new Error('noise send nonce exhausted');
        }
        const c = encryptWithAd(this.sendKey, this.sendNonce, new Uint8Array(), plain);
        this.sendNonce += 1n;
        const out = new Uint8Array(1 + c.length);
        out[0] = NOISE_DATA;
        out.set(c, 1);
        return out;
    }

    decryptFrame(frame: Uint8Array): Uint8Array {
        if (frame.length < 2 || frame[0] !== NOISE_DATA) {
            throw new Error('invalid encrypted frame');
        }
        if (this.recvNonce >= NOISE_NONCE_MAX) {
            throw new Error('noise recv nonce exhausted');
        }
        const plain = decryptWithAd(this.recvKey, this.recvNonce, new Uint8Array(), frame.slice(1));
        this.recvNonce += 1n;
        return plain;
    }
}

async function waitForBinaryFrame(ws: WebSocket, timeoutMs = 10000): Promise<Uint8Array> {
    return await new Promise<Uint8Array>((resolve, reject) => {
        const timer = window.setTimeout(() => {
            cleanup();
            reject(new Error('noise handshake timeout'));
        }, timeoutMs);
        const onMessage = (ev: MessageEvent) => {
            if (!(ev.data instanceof ArrayBuffer)) return;
            cleanup();
            resolve(new Uint8Array(ev.data));
        };
        const onClose = () => {
            cleanup();
            reject(new Error('websocket closed during noise handshake'));
        };
        const cleanup = () => {
            window.clearTimeout(timer);
            ws.removeEventListener('message', onMessage);
            ws.removeEventListener('close', onClose);
        };
        ws.addEventListener('message', onMessage);
        ws.addEventListener('close', onClose);
    });
}

async function doNoiseHandshake(ws: WebSocket): Promise<NoiseTransport> {
    let h = noiseProtocolState();
    let ck = h;

    const ePriv = randomBytes(32);
    const ePub = x25519.getPublicKey(ePriv);
    h = noiseMixHash(h, ePub);

    const hello = new Uint8Array(1 + ePub.length);
    hello[0] = NOISE_CLIENT_HELLO;
    hello.set(ePub, 1);
    ws.send(hello);

    const resp = await waitForBinaryFrame(ws);
    if (resp.length !== 49 || resp[0] !== NOISE_SERVER_HELLO) {
        throw new Error('invalid noise server hello');
    }
    const re = resp.slice(1, 33);
    const c = resp.slice(33);
    h = noiseMixHash(h, re);
    const dh = x25519.getSharedSecret(ePriv, re);
    const mix = noiseMixKey(ck, dh);
    ck = mix.ck;
    const plain = decryptWithAd(mix.tempKey, 0, h, c);
    if (plain.length !== 0) {
        throw new Error('invalid noise server payload');
    }
    h = noiseMixHash(h, c);
    const { k1, k2 } = noiseSplit(ck);
    return new NoiseTransport(k1, k2);
}

// ── file tree & file operations ───────────────────────────────────────────────

interface FileEntry {
    name: string;
    path: string;
    is_dir: boolean;
    size: number;
}

interface ApiResponse<T> {
    ok: boolean;
    data?: T;
    error?: string;
}

const fileTree = document.getElementById('file-tree') as HTMLUListElement;
const refreshBtn = document.getElementById('file-refresh-btn') as HTMLButtonElement;
const newFileBtn = document.getElementById('file-new-file-btn') as HTMLButtonElement;
const newDirBtn = document.getElementById('file-new-dir-btn') as HTMLButtonElement;
const renameBtn = document.getElementById('file-rename-btn') as HTMLButtonElement;
const deleteBtn = document.getElementById('file-delete-btn') as HTMLButtonElement;

const expandedDirs = new Set<string>(['']);
const childCache = new Map<string, FileEntry[]>();
let selectedPath = '';

function parentPath(p: string): string {
    const i = p.lastIndexOf('/');
    return i >= 0 ? p.slice(0, i) : '';
}

function pathJoin(parent: string, name: string): string {
    return parent ? `${parent}/${name}` : name;
}

async function apiGet<T>(path: string): Promise<T> {
    const res = await fetch(buildUrl(path));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as ApiResponse<T>;
    if (!body.ok) throw new Error(body.error ?? 'request failed');
    return body.data as T;
}

async function apiPost<T>(path: string, payload: unknown): Promise<T> {
    const res = await fetch(buildUrl(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as ApiResponse<T>;
    if (!body.ok) throw new Error(body.error ?? 'request failed');
    return body.data as T;
}

async function listDir(path = ''): Promise<FileEntry[]> {
    const qp = encodeURIComponent(path);
    const data = await apiGet<{ entries: FileEntry[] }>(`/api/files/list?path=${qp}`);
    return data.entries;
}

async function ensureChildren(path: string): Promise<FileEntry[]> {
    const cached = childCache.get(path);
    if (cached) return cached;
    const items = await listDir(path);
    childCache.set(path, items);
    return items;
}

async function hydrateExpanded(path: string): Promise<void> {
    const children = await ensureChildren(path);
    for (const item of children) {
        if (item.is_dir && expandedDirs.has(item.path)) {
            await hydrateExpanded(item.path);
        }
    }
}

function renderTreeRows(parentPathKey: string, depth: number, rows: HTMLLIElement[]) {
    const children = childCache.get(parentPathKey) ?? [];
    for (const item of children) {
        const li = document.createElement('li');
        li.style.paddingLeft = `${6 + depth * 16}px`;
        const expanded = item.is_dir && expandedDirs.has(item.path);
        const marker = item.is_dir ? (expanded ? '📂' : '📁') : '📄';
        li.textContent = `${marker} ${item.name}`;
        if (item.path === selectedPath) li.classList.add('selected');
        li.onclick = async () => {
            selectedPath = item.path;
            await renderFileTree();
        };
        li.ondblclick = async () => {
            if (!item.is_dir) return;
            if (expandedDirs.has(item.path)) expandedDirs.delete(item.path);
            else expandedDirs.add(item.path);
            if (expandedDirs.has(item.path)) await ensureChildren(item.path);
            await renderFileTree();
        };
        rows.push(li);
        if (item.is_dir && expandedDirs.has(item.path)) {
            renderTreeRows(item.path, depth + 1, rows);
        }
    }
}

async function renderFileTree() {
    try {
        await ensureChildren('');
        await hydrateExpanded('');
        const rows: HTMLLIElement[] = [];
        renderTreeRows('', 0, rows);
        fileTree.innerHTML = '';
        for (const row of rows) fileTree.appendChild(row);
    } catch (e) {
        console.error('[ttyd] file tree render failed', e);
    }
}

function selectedIsDir(): boolean {
    if (!selectedPath) return true;
    const parent = parentPath(selectedPath);
    const children = childCache.get(parent) ?? [];
    return children.find(x => x.path === selectedPath)?.is_dir ?? false;
}

function defaultCreateDir(): string {
    if (!selectedPath) return '';
    return selectedIsDir() ? selectedPath : parentPath(selectedPath);
}

async function refreshTree() {
    childCache.clear();
    await renderFileTree();
}

refreshBtn.onclick = () => { void refreshTree(); };
newFileBtn.onclick = async () => {
    const name = window.prompt('输入新文件名');
    if (!name) return;
    const dir = defaultCreateDir();
    try {
        await apiPost('/api/files/new-file', { path: dir, name });
        await refreshTree();
    } catch (e) {
        window.alert(String(e));
    }
};
newDirBtn.onclick = async () => {
    const name = window.prompt('输入新文件夹名');
    if (!name) return;
    const dir = defaultCreateDir();
    try {
        await apiPost('/api/files/mkdir', { path: dir, name });
        expandedDirs.add(pathJoin(dir, name));
        await refreshTree();
    } catch (e) {
        window.alert(String(e));
    }
};
renameBtn.onclick = async () => {
    if (!selectedPath) {
        window.alert('请先选择文件或目录');
        return;
    }
    const current = selectedPath.split('/').pop() ?? selectedPath;
    const newName = window.prompt('输入新名称', current);
    if (!newName || newName === current) return;
    try {
        await apiPost('/api/files/rename', { path: selectedPath, new_name: newName });
        selectedPath = pathJoin(parentPath(selectedPath), newName);
        await refreshTree();
    } catch (e) {
        window.alert(String(e));
    }
};
deleteBtn.onclick = async () => {
    if (!selectedPath) {
        window.alert('请先选择文件或目录');
        return;
    }
    if (!window.confirm(`确认删除 ${selectedPath} ?`)) return;
    try {
        await apiPost('/api/files/delete', { path: selectedPath });
        selectedPath = '';
        await refreshTree();
    } catch (e) {
        window.alert(String(e));
    }
};

// ── overlay helpers ──────────────────────────────────────────────────────────

const overlay = document.getElementById('overlay') as HTMLDivElement;
const overlayTitle = document.getElementById('overlay-title') as HTMLHeadingElement;
const overlayMsg = document.getElementById('overlay-msg') as HTMLParagraphElement;
const reconnectBtn = document.getElementById('reconnect-btn') as HTMLButtonElement;

function showOverlay(title: string, msg: string, showReconnect = false) {
    overlayTitle.textContent = title;
    overlayMsg.textContent = msg;
    reconnectBtn.style.display = showReconnect ? '' : 'none';
    overlay.classList.remove('hidden');
}

function hideOverlay() {
    overlay.classList.add('hidden');
}

// ── terminal setup ───────────────────────────────────────────────────────────

const termOptions: ITerminalOptions = {
    fontSize: 14,
    fontFamily: 'Consolas, "Liberation Mono", Menlo, Courier, monospace',
    theme: {
        foreground: '#d2d2d2',
        background: '#1e1e1e',
        cursor: '#adadad',
        black: '#000000',
        red: '#d81e00',
        green: '#5ea702',
        yellow: '#cfae00',
        blue: '#427ab3',
        magenta: '#89658e',
        cyan: '#00a7aa',
        white: '#dbded8',
        brightBlack: '#686a66',
        brightRed: '#f54235',
        brightGreen: '#99e343',
        brightYellow: '#fdeb61',
        brightBlue: '#84b0d8',
        brightMagenta: '#bc94b7',
        brightCyan: '#37e6e8',
        brightWhite: '#f1f1f0',
    },
    allowProposedApi: true,
    scrollback: 10000,
};

const term = new Terminal(termOptions);
const fitAddon = new FitAddon();
const unicode11 = new Unicode11Addon();
const webLinks = new WebLinksAddon();

term.loadAddon(fitAddon);
term.loadAddon(unicode11);
term.loadAddon(webLinks);
term.unicode.activeVersion = '11';

const container = document.getElementById('terminal') as HTMLDivElement;
term.open(container);

// Try WebGL renderer, fall back to Canvas, then DOM
try {
    const webgl = new WebglAddon();
    webgl.onContextLoss(() => webgl.dispose());
    term.loadAddon(webgl);
} catch {
    try {
        term.loadAddon(new CanvasAddon());
    } catch {
        // DOM renderer fallback (built in)
    }
}

fitAddon.fit();

// Resize observer to keep terminal fitted to window
let resizeTimer: number | null = null;
let resizeRaf: number | null = null;
let lastSentCols = -1;
let lastSentRows = -1;

function sendResizeIfChanged(cols: number, rows: number, force = false) {
    if (!force && cols === lastSentCols && rows === lastSentRows) return;
    lastSentCols = cols;
    lastSentRows = rows;
    sendResize(cols, rows);
}

function scheduleFitAndResize(delayMs = 30, force = false) {
    if (resizeTimer !== null) window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
        if (resizeRaf !== null) cancelAnimationFrame(resizeRaf);
        resizeRaf = requestAnimationFrame(() => {
            fitAddon.fit();
            sendResizeIfChanged(term.cols, term.rows, force);
        });
    }, delayMs);
}

const resizeObserver = new ResizeObserver(() => scheduleFitAndResize(30));
resizeObserver.observe(container);
window.addEventListener('resize', () => scheduleFitAndResize(30));
window.addEventListener('orientationchange', () => scheduleFitAndResize(60, true));
window.visualViewport?.addEventListener('resize', () => scheduleFitAndResize(30));

// ── WebSocket connection ─────────────────────────────────────────────────────

let ws: WebSocket | null = null;
let initialized = false;
let paused = false;
let wsNoiseEnabled = false;
let noiseTransport: NoiseTransport | null = null;
let noiseHandshakeInProgress = false;

// Flow control: buffer output while paused
const outputQueue: Uint8Array[] = [];
let enableZmodem = true;
let zmodemSentry: any = null;
let zmodemSession: any = null;

function stripZmodemNoise(octets: Uint8Array): Uint8Array {
    const out: number[] = [];
    for (let i = 0; i < octets.length;) {
        const prefixed = i + 4 < octets.length
            && octets[i] === 0x2a && octets[i + 1] === 0x2a
            && octets[i + 2] === 0x18 && octets[i + 3] === 0x42 && octets[i + 4] === 0x30;
        const plain = i + 3 < octets.length
            && octets[i] === 0x2a && octets[i + 1] === 0x2a
            && octets[i + 2] === 0x42 && octets[i + 3] === 0x30;

        if (prefixed || plain) {
            i += prefixed ? 5 : 4;
            while (i < octets.length) {
                const b = octets[i];
                const isHex = (b >= 0x30 && b <= 0x39)
                    || (b >= 0x41 && b <= 0x46)
                    || (b >= 0x61 && b <= 0x66);
                if (!isHex) break;
                i++;
            }
            continue;
        }

        out.push(octets[i]);
        i++;
    }
    return new Uint8Array(out);
}

function wsSendInput(data: string | Uint8Array) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !initialized) return;
    if (typeof data === 'string') data = enc.encode(data);
    const payload = new Uint8Array(1 + data.length);
    payload[0] = CMD_INPUT.charCodeAt(0);
    payload.set(data, 1);
    sendWire(payload);
}

function sendWire(data: string | Uint8Array) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!noiseTransport) {
        ws.send(data);
        return;
    }
    const plain = typeof data === 'string' ? enc.encode(data) : data;
    ws.send(noiseTransport.encryptFrame(plain));
}

function saveBlob(filename: string, parts: BlobPart[]) {
    const blob = new Blob(parts, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function resetZmodemState() {
    zmodemSession = null;
    term.options.disableStdin = false;
    term.focus();
}

function chooseFiles(): Promise<FileList> {
    return new Promise((resolve, reject) => {
        const input = document.createElement('input');
        input.type = 'file';
        input.multiple = true;
        input.style.display = 'none';
        document.body.appendChild(input);
        input.onchange = () => {
            const files = input.files;
            document.body.removeChild(input);
            if (!files || files.length === 0) {
                reject(new Error('no file selected'));
                return;
            }
            resolve(files);
        };
        input.click();
    });
}

async function startZmodemSend() {
    if (!zmodemSession) return;
    try {
        const files = await chooseFiles();
        await Zmodem.Browser.send_files(zmodemSession, files, {});
        zmodemSession.close();
    } catch {
        resetZmodemState();
    }
}

function startZmodemReceive() {
    if (!zmodemSession) return;
    zmodemSession.on('offer', (offer: any) => {
        offer
            .accept()
            .then((payloads: BlobPart[]) => {
                const name = offer.get_details().name ?? 'download.bin';
                saveBlob(name, payloads);
            })
            .catch(() => resetZmodemState());
    });
    zmodemSession.start();
}

function ensureZmodem() {
    if (!enableZmodem || zmodemSentry) return;
    zmodemSentry = new Zmodem.Sentry({
        to_terminal: (octets: number[]) => {
            const clean = stripZmodemNoise(new Uint8Array(octets));
            if (clean.length > 0) term.write(clean);
        },
        sender: (octets: number[]) => wsSendInput(new Uint8Array(octets)),
        on_retract: () => resetZmodemState(),
        on_detect: (detection: any) => {
            term.options.disableStdin = true;
            zmodemSession = detection.confirm();
            zmodemSession.on('session_end', () => resetZmodemState());
            if (zmodemSession.type === 'send') {
                void startZmodemSend();
            } else {
                startZmodemReceive();
            }
        },
    });
}

/** Fetch the auth token from /token */
async function fetchToken(): Promise<{ token: string; wsNoise: boolean }> {
    const res = await fetch(buildUrl('/token'));
    if (!res.ok) throw new Error(`token fetch failed: ${res.status}`);
    const data = await res.json() as { token?: string; ws_noise?: boolean };
    return {
        token: data.token ?? '',
        wsNoise: !!data.ws_noise,
    };
}

/** Send initial JSON handshake with auth token and window size */
function sendHandshake(token: string) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const { cols, rows } = term;
    const msg = JSON.stringify({ AuthToken: token, columns: cols, rows });
    sendWire(msg);
}

/** Send terminal resize notification */
function sendResize(cols: number, rows: number) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !initialized) return;
    const msg = CMD_RESIZE + JSON.stringify({ columns: cols, rows });
    sendWire(msg);
}

/** Called when terminal dimensions change */
term.onResize(({ cols, rows }) => {
    sendResizeIfChanged(cols, rows);
});

/** Forward keyboard / paste input to server */
term.onData((data: string) => {
    wsSendInput(data);
});

/** Handle binary messages from server */
function handleMessage(data: ArrayBuffer) {
    const buf = new Uint8Array(data);
    if (buf.length === 0) return;
    const cmd = buf[0];

    switch (cmd) {
        case SRV_OUTPUT: {
            let output = buf.slice(1);
            if (enableZmodem) {
                ensureZmodem();
                if (zmodemSentry) {
                    try {
                        zmodemSentry.consume(output);
                        break;
                    } catch {
                        resetZmodemState();
                        output = stripZmodemNoise(output);
                        if (output.length === 0) break;
                    }
                }
            }
            if (paused) {
                outputQueue.push(output);
                // Tell server to pause if queue is growing
                if (outputQueue.length > 10 && ws?.readyState === WebSocket.OPEN) {
                    sendWire(CMD_PAUSE);
                }
            } else {
                term.write(output);
            }
            break;
        }
        case SRV_SET_TITLE: {
            const title = dec.decode(buf.slice(1));
            document.title = title;
            break;
        }
        case SRV_SET_PREFS: {
            applyPrefs(dec.decode(buf.slice(1)));
            break;
        }
        default:
            break;
    }
}

/** Apply server-sent terminal preferences */
function applyPrefs(json: string) {
    try {
        const prefs = JSON.parse(json);
        if (typeof prefs.enableZmodem === 'boolean') {
            enableZmodem = prefs.enableZmodem;
        }
        // Apply supported xterm options from server preferences
        const supported: (keyof ITerminalOptions)[] = [
            'fontSize', 'fontFamily', 'cursorStyle', 'cursorBlink', 'scrollback', 'tabStopWidth',
        ];
        const update: Partial<ITerminalOptions> = {};
        for (const key of supported) {
            if (key in prefs) (update as Record<string, unknown>)[key] = prefs[key];
        }
        if (Object.keys(update).length > 0) term.options = { ...term.options, ...update };
        if (prefs.theme) term.options.theme = prefs.theme;
        scheduleFitAndResize(20, true);
    } catch {
        // ignore malformed prefs
    }
}

/** Flush buffered output when resumed */
function flushQueue() {
    while (outputQueue.length > 0) {
        const chunk = outputQueue.shift()!;
        term.write(chunk);
    }
}

/** Connect (or reconnect) to the server WebSocket */
async function connect() {
    showOverlay('Connecting…', 'Please wait');
    initialized = false;
    noiseTransport = null;
    wsNoiseEnabled = false;

    let tokenInfo: { token: string; wsNoise: boolean } = { token: '', wsNoise: false };
    try {
        tokenInfo = await fetchToken();
    } catch (e) {
        showOverlay('Connection Failed', String(e), true);
        return;
    }

    const wsUrl = buildWsUrl();
    ws = new WebSocket(wsUrl, ['tty']);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        void (async () => {
            try {
                if (tokenInfo.wsNoise) {
                    noiseHandshakeInProgress = true;
                    noiseTransport = await doNoiseHandshake(ws!);
                    wsNoiseEnabled = true;
                    noiseHandshakeInProgress = false;
                }
                hideOverlay();
                fitAddon.fit();
                sendHandshake(tokenInfo.token);
                initialized = true;
                lastSentCols = -1;
                lastSentRows = -1;
                ensureZmodem();
                term.focus();
                // Send current size after handshake
                scheduleFitAndResize(0, true);
            } catch (e) {
                noiseHandshakeInProgress = false;
                showOverlay('Connection Failed', String(e), true);
                ws?.close();
            }
        })();
    };

    ws.onmessage = (ev: MessageEvent) => {
        if (ev.data instanceof ArrayBuffer) {
            if (noiseHandshakeInProgress) return;
            try {
                let data = new Uint8Array(ev.data);
                if (wsNoiseEnabled && noiseTransport) {
                    data = noiseTransport.decryptFrame(data);
                }
                handleMessage(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
            } catch (e) {
                showOverlay('Connection Error', String(e), true);
                ws?.close();
            }
        }
    };

    ws.onclose = (ev: CloseEvent) => {
        initialized = false;
        zmodemSentry = null;
        resetZmodemState();
        const clean = ev.code === 1000;
        showOverlay(
            clean ? 'Connection Closed' : 'Disconnected',
            clean ? 'Terminal session ended.' : `Connection lost (code ${ev.code}).`,
            true,
        );
    };

    ws.onerror = () => {
        showOverlay('Connection Error', 'WebSocket error occurred.', true);
    };
}

// ── Start ────────────────────────────────────────────────────────────────────
void refreshTree();
connect();
