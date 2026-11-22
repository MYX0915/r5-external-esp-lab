// Screenshot an existing Edge tab.
// usage: node cdp-shot.mjs <port> <urlSubstring> <out.png>
import { writeFileSync } from 'node:fs';
const port = process.argv[2] || '9223';
const sub = process.argv[3] || 'drof.space';
const out = process.argv[4] || 'shot.png';

const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = list.find((t) => t.type === 'page' && (t.url || '').includes(sub));
if (!page) { console.error('not found'); process.exit(1); }

let id = 0; const pending = new Map();
const ws = new WebSocket(page.webSocketDebuggerUrl);
const send = (method, params = {}) => new Promise((res, rej) => { const mid = ++id; pending.set(mid, { res, rej }); ws.send(JSON.stringify({ id: mid, method, params })); });
ws.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } });
await new Promise((r, j) => { ws.addEventListener('open', r, { once: true }); ws.addEventListener('error', j, { once: true }); });
await send('Page.enable');
const r = await send('Page.captureScreenshot', { format: 'png' });
writeFileSync(out, Buffer.from(r.data, 'base64'));
console.log('saved', out);
ws.close(); process.exit(0);
