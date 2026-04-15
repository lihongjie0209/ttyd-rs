import { Terminal, ITerminalOptions } from '@xterm/xterm';
import '@picocss/pico/css/pico.min.css';
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
import * as monaco from 'monaco-editor';

// ── ttyd protocol constants ──────────────────────────────────────────────────

/** Client → Server */
const CMD_INPUT = '0';
const CMD_RESIZE = '1';
const CMD_PAUSE = '2';
const CMD_RESUME = '3';
const CMD_RPC = '4';

/** Server → Client */
const SRV_OUTPUT = 0x30; // '0'
const SRV_SET_TITLE = 0x31; // '1'
const SRV_SET_PREFS = 0x32; // '2'
const SRV_RPC = 0x34; // '4'

/** Noise transport */
const NOISE_CLIENT_HELLO = 0x90;
const NOISE_SERVER_HELLO = 0x91;
const NOISE_DATA = 0x92;
const NOISE_PROTOCOL = 'Noise_NN_25519_ChaChaPoly_SHA256';
const PLAINTEXT_SERVER_CMDS = new Set<number>([SRV_OUTPUT, SRV_SET_TITLE, SRV_SET_PREFS, SRV_RPC]);

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

class PlaintextWsFallbackError extends Error {
    constructor(public firstFrame: Uint8Array) {
        super('server is running without ws noise');
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
    const respPromise = waitForBinaryFrame(ws);
    ws.send(hello);

    const resp = await respPromise;
    if (resp.length !== 49 || resp[0] !== NOISE_SERVER_HELLO) {
        if (PLAINTEXT_SERVER_CMDS.has(resp[0])) {
            throw new PlaintextWsFallbackError(resp);
        }
        throw new Error('invalid noise server hello');
    }
    const re = resp.slice(1, 33);
    const c = resp.slice(33);
    h = noiseMixHash(h, re);
    const dh = x25519.getSharedSecret(ePriv, re);
    const mix = noiseMixKey(ck, dh);
    ck = mix.ck;
    const plain = decryptWithAd(mix.tempKey, 0n, h, c);
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
const uploadBtn = document.getElementById('file-upload-btn') as HTMLButtonElement;
const downloadBtn = document.getElementById('file-download-btn') as HTMLButtonElement;
const fileContextMenu = document.getElementById('file-context-menu') as HTMLDivElement;
const moreBtn = document.getElementById('file-more-btn') as HTMLButtonElement;
const moreList = document.getElementById('file-more-list') as HTMLDivElement;
const uiModal = document.getElementById('ui-modal') as HTMLDivElement;
const uiModalTitle = document.getElementById('ui-modal-title') as HTMLHeadingElement;
const uiModalMessage = document.getElementById('ui-modal-message') as HTMLParagraphElement;
const uiModalInput = document.getElementById('ui-modal-input') as HTMLInputElement;
const uiModalCancelBtn = document.getElementById('ui-modal-cancel-btn') as HTMLButtonElement;
const uiModalOkBtn = document.getElementById('ui-modal-ok-btn') as HTMLButtonElement;

moreBtn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const open = !moreList.classList.contains('hidden');
    moreList.classList.toggle('hidden', open);
    moreBtn.classList.toggle('active', !open);
});

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

function bytesToBase64(bytes: Uint8Array): string {
    const chunkSize = 0x8000;
    let bin = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        bin += String.fromCharCode(...chunk);
    }
    return btoa(bin);
}

function base64ToBytes(base64: string): Uint8Array {
    const bin = atob(base64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

type DialogKind = 'alert' | 'confirm' | 'prompt';

function showDialog(kind: DialogKind, title: string, message: string, value = ''): Promise<string | boolean | null> {
    return new Promise((resolve) => {
        uiModalTitle.textContent = title;
        uiModalMessage.textContent = message;
        uiModal.classList.remove('hidden');
        uiModalInput.value = value;

        const promptMode = kind === 'prompt';
        const cancelVisible = kind !== 'alert';
        uiModalInput.classList.toggle('hidden', !promptMode);
        uiModalCancelBtn.classList.toggle('hidden', !cancelVisible);
        uiModalOkBtn.textContent = kind === 'alert' ? '知道了' : '确认';

        const done = (result: string | boolean | null) => {
            uiModal.classList.add('hidden');
            uiModalOkBtn.onclick = null;
            uiModalCancelBtn.onclick = null;
            uiModal.onclick = null;
            uiModalInput.onkeydown = null;
            resolve(result);
        };

        uiModalOkBtn.onclick = () => {
            if (kind === 'confirm') done(true);
            else if (kind === 'prompt') done(uiModalInput.value.trim());
            else done(true);
        };
        uiModalCancelBtn.onclick = () => done(false);
        uiModal.onclick = (ev) => {
            if (ev.target === uiModal) done(kind === 'alert' ? true : false);
        };
        uiModalInput.onkeydown = (ev) => {
            if (ev.key === 'Enter') uiModalOkBtn.click();
            if (ev.key === 'Escape') done(false);
        };

        if (promptMode) {
            queueMicrotask(() => {
                uiModalInput.focus();
                uiModalInput.select();
            });
        } else {
            queueMicrotask(() => uiModalOkBtn.focus());
        }
    });
}

async function uiAlert(message: string, title = '提示') {
    await showDialog('alert', title, message);
}

async function uiConfirm(message: string, title = '确认') {
    return (await showDialog('confirm', title, message)) === true;
}

async function uiPrompt(title: string, defaultValue = '') {
    const result = await showDialog('prompt', title, '', defaultValue);
    if (typeof result !== 'string') return null;
    const trimmed = result.trim();
    return trimmed.length > 0 ? trimmed : null;
}

async function listDir(path = ''): Promise<FileEntry[]> {
    const data = await wsRpc<{ entries: FileEntry[] }>('file.list', { path });
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

const FILE_ICONS: Record<string, string> = {
    // Folder icons are handled separately
    ts: '#4a9eff', tsx: '#4a9eff', js: '#f0db4f', jsx: '#61dafb',
    rs: '#f74c00', py: '#3572A5', go: '#00add8', java: '#b07219',
    cpp: '#f34b7d', c: '#555555', h: '#555555', cs: '#178600',
    html: '#e34c26', css: '#563d7c', scss: '#c6538c', json: '#cbcb41',
    md: '#083fa1', txt: '#aaa', sh: '#89e051', bash: '#89e051',
    yaml: '#cb171e', yml: '#cb171e', toml: '#9c4221', xml: '#0060ac',
    sql: '#e38c00', svg: '#ff9900', png: '#6e4c13', jpg: '#6e4c13',
    jpeg: '#6e4c13', gif: '#6e4c13', ico: '#6e4c13', webp: '#6e4c13',
    pdf: '#b30b00', zip: '#8a5a28', gz: '#8a5a28', tar: '#8a5a28',
};

function getFileIconSvg(name: string, isDir: boolean, expanded: boolean): string {
    if (isDir) {
        if (expanded) {
            return `<svg viewBox="0 0 16 16" fill="none"><path d="M1.5 3.5A1.5 1.5 0 0 1 3 2h3.379a1.5 1.5 0 0 1 1.06.44l.622.622A1.5 1.5 0 0 0 9.12 3.5H13A1.5 1.5 0 0 1 14.5 5v1H2V3.5Zm-1 3.25v5.75A1.5 1.5 0 0 0 2 14h12a1.5 1.5 0 0 0 1.5-1.5V6.75Z" fill="#e8a84b"/></svg>`;
        }
        return `<svg viewBox="0 0 16 16" fill="none"><path d="M2 3.5A1.5 1.5 0 0 1 3.5 2h3.378a1.5 1.5 0 0 1 1.06.44l.622.622A1.5 1.5 0 0 0 9.62 3.5H12.5A1.5 1.5 0 0 1 14 5v7.5A1.5 1.5 0 0 1 12.5 14h-9A1.5 1.5 0 0 1 2 12.5Z" fill="#6699cc"/></svg>`;
    }
    const ext = name.includes('.') ? name.split('.').pop()!.toLowerCase() : '';
    const color = FILE_ICONS[ext] ?? '#7a9ab8';
    return `<svg viewBox="0 0 16 16" fill="none"><path d="M4 2h6.414L13 4.586V14H3V2h1zm6 0v2.5H12.5" stroke="${color}" stroke-width="1.2"/></svg>`;
}

function renderTreeRows(parentPathKey: string, depth: number, rows: HTMLLIElement[]) {
    const children = childCache.get(parentPathKey) ?? [];
    if (children.length === 0 && depth === 0) {
        const li = document.createElement('li');
        li.className = 'empty-tree';
        li.innerHTML = `<svg width="28" height="28" viewBox="0 0 16 16" fill="none"><path d="M2 3.5A1.5 1.5 0 0 1 3.5 2h3.378a1.5 1.5 0 0 1 1.06.44l.622.622A1.5 1.5 0 0 0 9.62 3.5H12.5A1.5 1.5 0 0 1 14 5v7.5A1.5 1.5 0 0 1 12.5 14h-9A1.5 1.5 0 0 1 2 12.5Z" fill="#2a3d52"/></svg><span>暂无文件</span>`;
        rows.push(li);
        return;
    }
    for (const item of children) {
        const li = document.createElement('li');
        li.dataset.path = item.path;
        li.dataset.isDir = item.is_dir ? '1' : '0';
        const expanded = item.is_dir && expandedDirs.has(item.path);

        const inner = document.createElement('div');
        inner.className = 'tree-row-inner';

        // Indent
        if (depth > 0) {
            const indent = document.createElement('span');
            indent.className = 'tree-indent';
            indent.style.width = `${depth * 16}px`;
            inner.appendChild(indent);
        }

        // Toggle arrow for dirs
        if (item.is_dir) {
            const toggle = document.createElement('span');
            toggle.className = 'tree-toggle' + (expanded ? ' expanded' : '');
            toggle.innerHTML = `<svg width="10" height="10" viewBox="0 0 10 10"><path d="M3 2l4 3-4 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
            inner.appendChild(toggle);
        } else {
            const spacer = document.createElement('span');
            spacer.style.width = '14px';
            spacer.style.flexShrink = '0';
            inner.appendChild(spacer);
        }

        // File icon
        const iconEl = document.createElement('span');
        iconEl.className = 'tree-icon';
        iconEl.innerHTML = getFileIconSvg(item.name, item.is_dir, expanded);
        inner.appendChild(iconEl);

        // Name
        const nameEl = document.createElement('span');
        nameEl.className = 'tree-name';
        nameEl.textContent = item.name;
        nameEl.title = item.path;
        inner.appendChild(nameEl);

        li.appendChild(inner);
        if (item.path === selectedPath) li.classList.add('selected');

        li.onclick = async (ev: MouseEvent) => {
            ev.stopPropagation();
            selectedPath = item.path;
            if (item.is_dir) {
                if (expandedDirs.has(item.path)) expandedDirs.delete(item.path);
                else { expandedDirs.add(item.path); await ensureChildren(item.path); }
            }
            await renderFileTree();
        };
        if (!item.is_dir) {
            li.ondblclick = (ev: MouseEvent) => {
                ev.stopPropagation();
                void openFileInEditor(item.path);
            };
        }
        li.oncontextmenu = async (ev: MouseEvent) => {
            ev.preventDefault();
            selectedPath = item.path;
            await renderFileTree();
            showContextMenu(ev.clientX, ev.clientY);
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

function hideContextMenu() {
    fileContextMenu.style.display = 'none';
}

function showContextMenu(x: number, y: number) {
    // Show "编辑" only for files, not directories
    const editBtn = fileContextMenu.querySelector('button[data-action="edit"]') as HTMLButtonElement | null;
    if (editBtn) {
        const isDir = selectedIsDir();
        editBtn.style.display = isDir ? 'none' : '';
    }
    const maxX = window.innerWidth - fileContextMenu.offsetWidth - 8;
    const maxY = window.innerHeight - fileContextMenu.offsetHeight - 8;
    fileContextMenu.style.left = `${Math.max(8, Math.min(x, maxX))}px`;
    fileContextMenu.style.top = `${Math.max(8, Math.min(y, maxY))}px`;
    fileContextMenu.style.display = 'block';
}

fileTree.oncontextmenu = (ev: MouseEvent) => {
    if ((ev.target as HTMLElement).closest('li')) return;
    ev.preventDefault();
    selectedPath = '';
    void renderFileTree().then(() => showContextMenu(ev.clientX, ev.clientY));
};

document.addEventListener('click', () => { hideContextMenu(); moreList.classList.add('hidden'); moreBtn.classList.remove('active'); });
window.addEventListener('blur', () => hideContextMenu());
window.addEventListener('resize', () => hideContextMenu());

async function createNewFile() {
    const name = await uiPrompt('输入新文件名');
    if (!name) return;
    const dir = defaultCreateDir();
    try {
        await wsRpc('file.new-file', { path: dir, name });
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '创建失败');
    }
}

async function createNewDir() {
    const name = await uiPrompt('输入新文件夹名');
    if (!name) return;
    const dir = defaultCreateDir();
    try {
        await wsRpc('file.mkdir', { path: dir, name });
        expandedDirs.add(pathJoin(dir, name));
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '创建失败');
    }
}

async function renameSelected() {
    if (!selectedPath) {
        await uiAlert('请先选择文件或目录');
        return;
    }
    const current = selectedPath.split('/').pop() ?? selectedPath;
    const newName = await uiPrompt('输入新名称', current);
    if (!newName || newName === current) return;
    try {
        await wsRpc('file.rename', { path: selectedPath, new_name: newName });
        selectedPath = pathJoin(parentPath(selectedPath), newName);
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '重命名失败');
    }
}

async function deleteSelected() {
    if (!selectedPath) {
        await uiAlert('请先选择文件或目录');
        return;
    }
    if (!(await uiConfirm(`确认删除 ${selectedPath} ?`))) return;
    try {
        await wsRpc('file.delete', { path: selectedPath });
        selectedPath = '';
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '删除失败');
    }
}

async function uploadToDir(dir: string) {
    try {
        const files = await chooseFiles();
        for (const file of Array.from(files)) {
            const content = new Uint8Array(await file.arrayBuffer());
            await wsRpc('file.upload', {
                path: dir,
                name: file.name,
                content_base64: bytesToBase64(content),
                overwrite: true,
            });
        }
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '上传失败');
    }
}

async function uploadSelected() {
    await uploadToDir(defaultCreateDir());
}

async function downloadSelected() {
    if (!selectedPath) {
        await uiAlert('请先选择要下载的文件或目录');
        return;
    }
    try {
        const data = await wsRpc<{ name: string; content_base64: string }>('file.download', { path: selectedPath });
        const bytes = base64ToBytes(data.content_base64);
        saveBlob(data.name || 'download.bin', [bytes]);
    } catch (e) {
        await uiAlert(String(e), '下载失败');
    }
}

refreshBtn.onclick = () => { void refreshTree(); };
newFileBtn.onclick = () => { void createNewFile(); };
newDirBtn.onclick = () => { void createNewDir(); };
renameBtn.onclick = () => { void renameSelected(); };
deleteBtn.onclick = () => { void deleteSelected(); };
uploadBtn.onclick = () => { void uploadSelected(); };
downloadBtn.onclick = () => { void downloadSelected(); };

// Logout button
const logoutBtn = document.getElementById('logout-btn') as HTMLButtonElement | null;
if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
        try {
            await fetch('/logout', { method: 'POST', credentials: 'include' });
        } catch (_) { /* ignore network errors */ }
        window.location.href = '/login';
    });
}

// ── drag & drop upload ────────────────────────────────────────────────────────

async function uploadFilesTo(dir: string, files: FileList | File[]) {
    const arr = Array.from(files);
    if (arr.length === 0) return;
    try {
        for (const file of arr) {
            const content = new Uint8Array(await file.arrayBuffer());
            await wsRpc('file.upload', {
                path: dir,
                name: file.name,
                content_base64: bytesToBase64(content),
                overwrite: true,
            });
        }
        await refreshTree();
    } catch (e) {
        await uiAlert(String(e), '上传失败');
    }
}

/** Return the directory path for a drop target element (li or the tree root). */
function dropTargetDir(target: EventTarget | null): string {
    const li = (target as HTMLElement | null)?.closest('li[data-path]') as HTMLLIElement | null;
    if (!li) return '';
    const path = li.dataset.path ?? '';
    const isDir = li.dataset.isDir === '1';
    return isDir ? path : parentPath(path);
}

fileTree.addEventListener('dragenter', (ev) => {
    ev.preventDefault();
    const li = (ev.target as HTMLElement).closest('li[data-path]') as HTMLLIElement | null;
    if (li) {
        li.classList.add('drag-over');
    } else {
        fileTree.classList.add('drag-over-root');
    }
});

fileTree.addEventListener('dragover', (ev) => {
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'copy';
});

fileTree.addEventListener('dragleave', (ev) => {
    const li = (ev.target as HTMLElement).closest('li[data-path]') as HTMLLIElement | null;
    if (li) {
        li.classList.remove('drag-over');
    } else {
        fileTree.classList.remove('drag-over-root');
    }
});

fileTree.addEventListener('drop', (ev) => {
    ev.preventDefault();
    // Clear all highlights
    fileTree.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
    fileTree.classList.remove('drag-over-root');
    const files = ev.dataTransfer?.files;
    if (!files || files.length === 0) return;
    const dir = dropTargetDir(ev.target);
    void uploadFilesTo(dir, files);
});

fileContextMenu.addEventListener('click', (ev) => {
    const target = ev.target as HTMLElement;
    const btn = target.closest('button[data-action]') as HTMLButtonElement | null;
    if (!btn) return;
    const action = btn.dataset.action;
    hideContextMenu();
    switch (action) {
        case 'refresh':
            void refreshTree();
            break;
        case 'upload':
            void uploadSelected();
            break;
        case 'download':
            void downloadSelected();
            break;
        case 'new-file':
            void createNewFile();
            break;
        case 'new-dir':
            void createNewDir();
            break;
        case 'edit':
            void openFileInEditor(selectedPath);
            break;
        case 'rename':
            void renameSelected();
            break;
        case 'delete':
            void deleteSelected();
            break;
        default:
            break;
    }
});

// ── Monaco Editor ────────────────────────────────────────────────────────────

// Configure Monaco to use empty inline workers so it doesn't request external worker files.
// Syntax highlighting (Monarch tokenizers) runs on the main thread; workers only add
// IntelliSense/validation which we don't need for a basic file editor.
(window as any).MonacoEnvironment = {
    getWorker(_moduleId: string, _label: string) {
        const blob = new Blob([''], { type: 'application/javascript' });
        return new Worker(URL.createObjectURL(blob));
    },
};

const editorPane = document.getElementById('editor-pane') as HTMLDivElement;
const editorContainer = document.getElementById('editor-container') as HTMLDivElement;
const editorFilename = document.getElementById('editor-filename') as HTMLSpanElement;
const editorDirtyDot = document.getElementById('editor-dirty-dot') as HTMLSpanElement;
const editorLangBadge = document.getElementById('editor-lang-badge') as HTMLSpanElement;
const editorSaveBtn = document.getElementById('editor-save-btn') as HTMLButtonElement;
const editorCloseBtn = document.getElementById('editor-close-btn') as HTMLButtonElement;

let editorInstance: monaco.editor.IStandaloneCodeEditor | null = null;
let currentEditorPath = '';
let editorDirty = false;

function getMonacoLang(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase() ?? '';
    const map: Record<string, string> = {
        ts: 'typescript', tsx: 'typescript',
        js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
        rs: 'rust',
        py: 'python',
        json: 'json', jsonc: 'json',
        html: 'html', htm: 'html',
        css: 'css', scss: 'scss', less: 'less',
        md: 'markdown', markdown: 'markdown',
        sh: 'shell', bash: 'shell', zsh: 'shell', fish: 'shell',
        yaml: 'yaml', yml: 'yaml',
        toml: 'ini',
        xml: 'xml', svg: 'xml',
        sql: 'sql',
        go: 'go',
        java: 'java',
        c: 'c', h: 'c',
        cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
        cs: 'csharp',
        rb: 'ruby',
        php: 'php',
        swift: 'swift',
        kt: 'kotlin', kts: 'kotlin',
        dockerfile: 'dockerfile',
        makefile: 'makefile',
        ini: 'ini', conf: 'ini', cfg: 'ini',
        txt: 'plaintext',
    };
    // Special filenames
    const lower = filename.toLowerCase();
    if (lower === 'dockerfile') return 'dockerfile';
    if (lower === 'makefile' || lower === 'gnumakefile') return 'makefile';
    return map[ext] ?? 'plaintext';
}

function setEditorDirty(dirty: boolean) {
    editorDirty = dirty;
    editorDirtyDot.classList.toggle('hidden', !dirty);
}

async function openFileInEditor(path: string): Promise<void> {
    if (!path || path === '') {
        await uiAlert('请先选择一个文件');
        return;
    }
    // Check if it looks like a directory (no extension is fine, we try to open)
    try {
        const result = await wsRpc<{ path: string; content_base64: string; size: number }>('file.read', { path });
        const filename = path.split('/').pop() ?? path;
        const lang = getMonacoLang(filename);
        const content = atob(result.content_base64);

        currentEditorPath = path;

        if (!editorInstance) {
            editorInstance = monaco.editor.create(editorContainer, {
                value: content,
                language: lang,
                theme: 'vs-dark',
                automaticLayout: true,
                fontSize: 13,
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                minimap: { enabled: true },
                scrollBeyondLastLine: false,
                wordWrap: 'off',
                tabSize: 4,
                renderWhitespace: 'selection',
                lineNumbers: 'on',
                folding: true,
                bracketPairColorization: { enabled: true },
                suggestOnTriggerCharacters: true,
            });
            editorInstance.onDidChangeModelContent(() => {
                if (!editorDirty) setEditorDirty(true);
            });
            editorInstance.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
                void saveCurrentFile();
            });
        } else {
            const model = editorInstance.getModel();
            if (model) {
                monaco.editor.setModelLanguage(model, lang);
                editorInstance.setValue(content);
            } else {
                const newModel = monaco.editor.createModel(content, lang);
                editorInstance.setModel(newModel);
            }
        }

        editorFilename.textContent = filename;
        editorLangBadge.textContent = lang;
        setEditorDirty(false);

        editorPane.classList.remove('hidden');
    } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        await uiAlert(`无法打开文件: ${msg}`);
    }
}

async function saveCurrentFile(): Promise<void> {
    if (!editorInstance || !currentEditorPath) return;
    const content = editorInstance.getValue();
    // Encode content to base64
    const bytes = new TextEncoder().encode(content);
    const content_base64 = bytesToBase64(bytes);
    try {
        await wsRpc('file.write', { path: currentEditorPath, content_base64 });
        setEditorDirty(false);
    } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        await uiAlert(`保存失败: ${msg}`);
    }
}

editorSaveBtn.addEventListener('click', () => { void saveCurrentFile(); });

editorCloseBtn.addEventListener('click', async () => {
    if (editorDirty) {
        if (!(await uiConfirm('文件有未保存的修改，确认关闭？'))) return;
    }
    editorPane.classList.add('hidden');
    currentEditorPath = '';
    setEditorDirty(false);
});

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
let wsRpcSeq = 1;
const wsRpcPending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();

function wsRpc<T>(method: string, params: unknown): Promise<T> {
    if (!ws || ws.readyState !== WebSocket.OPEN || !initialized) {
        return Promise.reject(new Error('websocket is not ready'));
    }
    const id = wsRpcSeq++;
    return new Promise<T>((resolve, reject) => {
        wsRpcPending.set(id, { resolve: resolve as (v: unknown) => void, reject });
        const body = JSON.stringify({ id, method, params });
        sendWire(CMD_RPC + body);
    });
}

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

/** Send initial JSON handshake with window size */
function sendHandshake() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const { cols, rows } = term;
    const msg = JSON.stringify({ columns: cols, rows });
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
        case SRV_RPC: {
            try {
                const payload = JSON.parse(dec.decode(buf.slice(1))) as ApiResponse<unknown> & { id?: number };
                const id = Number(payload.id ?? 0);
                const pending = wsRpcPending.get(id);
                if (!pending) break;
                wsRpcPending.delete(id);
                if (payload.ok) pending.resolve(payload.data);
                else pending.reject(new Error(payload.error ?? 'rpc failed'));
            } catch {
                // ignore malformed rpc payload
            }
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

    const wsUrl = buildWsUrl();
    ws = new WebSocket(wsUrl, ['tty']);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        void (async () => {
            try {
                noiseHandshakeInProgress = true;
                noiseTransport = await doNoiseHandshake(ws!);
                wsNoiseEnabled = true;
                noiseHandshakeInProgress = false;
                hideOverlay();
                fitAddon.fit();
                sendHandshake();
                initialized = true;
                lastSentCols = -1;
                lastSentRows = -1;
                ensureZmodem();
                void refreshTree();
                term.focus();
                // Send current size after handshake
                scheduleFitAndResize(0, true);
            } catch (e) {
                noiseHandshakeInProgress = false;
                if (e instanceof PlaintextWsFallbackError) {
                    wsNoiseEnabled = false;
                    noiseTransport = null;
                    handleMessage(e.firstFrame.buffer.slice(
                        e.firstFrame.byteOffset,
                        e.firstFrame.byteOffset + e.firstFrame.byteLength,
                    ));
                    hideOverlay();
                    sendHandshake();
                    initialized = true;
                    lastSentCols = -1;
                    lastSentRows = -1;
                    ensureZmodem();
                    void refreshTree();
                    term.focus();
                    scheduleFitAndResize(0, true);
                    return;
                }
                console.error(e);
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
                console.error(e);
                showOverlay('Connection Error', String(e), true);
                ws?.close();
            }
        }
    };

    ws.onclose = (ev: CloseEvent) => {
        initialized = false;
        for (const [, pending] of wsRpcPending) {
            pending.reject(new Error('websocket closed'));
        }
        wsRpcPending.clear();
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
connect();
