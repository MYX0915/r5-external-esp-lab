// Grab a fully-rendered (Cloudflare-challenged) page via an already-running Edge instance.
// usage: node cdp-grab.mjs <port> <outfile> [waitMs]
const port = process.argv[2] || '9223';
const out = process.argv[3] || 'page.html';
const waitMs = Number(process.argv[4] || 20000);
import { writeFileSync } from 'node:fs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function targets() {
  const r = await fetch(`http://127.0.0.1:${port}/json/list`);
  return r.json();
}

let page = null;
for (let i = 0; i < 40; i++) {
  try {
    const list = await targets();
    page =
      list.find((t) => t.type === 'page' && /^https?:/.test(t.url || '')) ||
      list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    if (page) break;
  } catch {}
  await sleep(500);
}
if (!page) {
  console.error('no page target');
  process.exit(1);
}
console.log('target:', page.url);

let id = 0;
const pending = new Map();
const ws = new WebSocket(page.webSocketDebuggerUrl);
const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const mid = ++id;
    pending.set(mid, { resolve, reject });
    ws.send(JSON.stringify({ id: mid, method, params }));
  });

ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
});

await new Promise((res, rej) => {
  ws.addEventListener('open', res, { once: true });
  ws.addEventListener('error', rej, { once: true });
});

await send('Page.enable');
await send('Runtime.enable');

// wait for the CF challenge to clear: title must stop being the interstitial
const deadline = Date.now() + waitMs;
let title = '';
while (Date.now() < deadline) {
  const r = await send('Runtime.evaluate', {
    expression: 'JSON.stringify({t:document.title, len:document.documentElement.outerHTML.length})',
    returnByValue: true,
  });
  const info = JSON.parse(r.result.value);
  title = info.t;
  console.log(`  title="${title}" html=${info.len}`);
  if (!/请稍候|Just a moment|稍候/.test(title) && info.len > 20000) break;
  await sleep(2000);
}

const html = await send('Runtime.evaluate', {
  expression: 'document.documentElement.outerHTML',
  returnByValue: true,
});
writeFileSync(out, html.result.value, 'utf8');
console.log('saved', out, html.result.value.length, 'title:', title);
ws.close();
process.exit(0);
