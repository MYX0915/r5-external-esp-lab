// Connect to an existing Edge tab matching a URL substring, focus it, wait out the
// Cloudflare interstitial (Turnstile), optionally click the checkbox, dump the DOM.
// usage: node cdp-wait.mjs <port> <urlSubstring> <outfile> [waitMs] [click]
const port = process.argv[2] || '9223';
const sub = process.argv[3] || 'drof.space';
const out = process.argv[4] || 'page.html';
const waitMs = Number(process.argv[5] || 90000);
const doClick = process.argv[6] === 'click';
import { writeFileSync } from 'node:fs';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = list.find((t) => t.type === 'page' && (t.url || '').includes(sub));
if (!page) {
  console.error('target not found');
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
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { resolve, reject } = pending.get(m.id);
    pending.delete(m.id);
    m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result);
  }
});
await new Promise((res, rej) => {
  ws.addEventListener('open', res, { once: true });
  ws.addEventListener('error', rej, { once: true });
});

await send('Page.enable');
await send('Runtime.enable');
try {
  await send('Page.bringToFront');
} catch {}

const evalJs = async (expr) =>
  (await send('Runtime.evaluate', { expression: expr, returnByValue: true })).result.value;

let clicked = false;
const deadline = Date.now() + waitMs;
let title = '';
while (Date.now() < deadline) {
  title = await evalJs('document.title');
  const len = await evalJs('document.documentElement.outerHTML.length');
  console.log(`  title="${title}" html=${len}`);
  if (!/请稍候|Just a moment/.test(title) && len > 20000) break;
  if (doClick && !clicked) {
    const rect = await evalJs(`(() => {
      const f = document.querySelector('iframe[src*="challenges.cloudflare.com"]');
      if (!f) return null;
      const r = f.getBoundingClientRect();
      return JSON.stringify({x: r.x + 30, y: r.y + r.height / 2});
    })()`);
    if (rect) {
      const { x, y } = JSON.parse(rect);
      for (const type of ['mousePressed', 'mouseReleased']) {
        await send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
      }
      clicked = true;
      console.log('  clicked turnstile at', x, y);
    }
  }
  await sleep(3000);
}

const html = await evalJs('document.documentElement.outerHTML');
writeFileSync(out, html, 'utf8');
console.log('saved', out, html.length, 'final title:', title);
ws.close();
process.exit(0);
