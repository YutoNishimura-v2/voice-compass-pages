// Service Worker for the encrypted GitHub Pages build (tools/pages/encrypt-build.mjs).
// Every file under this scope except the loader, this worker and the icons is stored
// as [12-byte IV][AES-256-GCM ciphertext]. The key lives in this origin's IndexedDB,
// put there by the loader page from the private link (#k=...), and never leaves the device.
const PLAIN = new Set(["", "index.html", "sw.js", "loader.webmanifest", "favicon.svg", "icon-192.png", "icon-512.png", "robots.txt"]);
const TYPES = {
  html: "text/html; charset=utf-8", js: "text/javascript", mjs: "text/javascript", css: "text/css", json: "application/json",
  webmanifest: "application/manifest+json", wasm: "application/wasm", mp3: "audio/mpeg", wav: "audio/wav", png: "image/png",
  svg: "image/svg+xml", onnx: "application/octet-stream", gz: "application/gzip", txt: "text/plain",
};
const base = new URL(self.registration.scope).pathname;
let keyPromise = null;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", event => event.waitUntil(self.clients.claim()));
self.addEventListener("message", event => { if (event.data === "key-changed") keyPromise = null; });

function readKey() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("voice-compass-pages", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const get = open.result.transaction("keys").objectStore("keys").get("k");
      get.onsuccess = () => { open.result.close(); resolve(get.result ?? null); };
      get.onerror = () => reject(get.error);
    };
  });
}
async function cryptoKey() {
  keyPromise ??= readKey().then(raw => raw ? crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]) : null);
  const key = await keyPromise;
  if (!key) keyPromise = null;
  return key;
}

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(base) || event.request.method !== "GET") return;
  const relative = decodeURIComponent(url.pathname.slice(base.length));
  if (PLAIN.has(relative)) return;
  event.respondWith(decrypted(event.request, url, relative));
});

async function decrypted(request, url, relative) {
  const key = await cryptoKey();
  if (!key) return new Response("鍵がありません。鍵つきリンクから開いてください。", { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  // Fetch the stored ciphertext without the Range header: ranges are cut after decryption.
  const stored = await fetch(url.href, { cache: request.cache === "only-if-cached" ? "default" : request.cache, credentials: "same-origin" });
  if (!stored.ok) return new Response(null, { status: stored.status, statusText: stored.statusText });
  const sealed = new Uint8Array(await stored.arrayBuffer());
  let plain;
  try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(0, 12) }, key, sealed.subarray(12))); }
  catch { return new Response("復号できませんでした。鍵が違う可能性があります。", { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8" } }); }
  const extension = (relative.split("?")[0].split(".").pop() ?? "").toLowerCase();
  const headers = { "Content-Type": TYPES[extension] ?? "application/octet-stream", "Accept-Ranges": "bytes", "Cache-Control": "no-store" };
  // Safari streams <audio> with byte ranges and needs 206 answers.
  const range = /^bytes=(\d*)-(\d*)$/.exec(request.headers.get("Range") ?? "");
  if (range) {
    const total = plain.length, start = range[1] === "" ? Math.max(0, total - Number(range[2])) : Number(range[1]);
    const end = range[1] !== "" && range[2] !== "" ? Math.min(total - 1, Number(range[2])) : total - 1;
    if (start >= total || start > end) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${total}` } });
    return new Response(plain.slice(start, end + 1), { status: 206, headers: { ...headers, "Content-Range": `bytes ${start}-${end}/${total}`, "Content-Length": String(end - start + 1) } });
  }
  return new Response(plain, { status: 200, headers: { ...headers, "Content-Length": String(plain.length) } });
}
