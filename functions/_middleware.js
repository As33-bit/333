const ALLOWED_IPS = new Set([
  "52.192.113.75",
  "172.216.227.77",
  "172.216.137.185",
]);

const COOKIE = "__Host-finance_session";
const TTL = 12 * 60 * 60;

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const ip = request.headers.get("CF-Connecting-IP") || "";

  if (!ALLOWED_IPS.has(ip)) {
    return html(`<h2>此 IP 未授權</h2><p class="message">目前來源 IP：${esc(ip || "無法取得")}</p>`, 403);
  }

  if (!env.LOGIN_USER || !env.LOGIN_PASS || !env.SESSION_SECRET) {
    return html("<h2>Cloudflare Secret 尚未設定完成</h2>", 500);
  }

  if (url.pathname === "/logout") {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/login",
        "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
        "Cache-Control": "no-store",
      },
    });
  }

  if (url.pathname === "/login") {
    if (request.method === "GET") {
      if (await validSession(request, env.SESSION_SECRET, ip)) return redirect("/");
      return html(loginPage(""));
    }

    if (request.method === "POST") {
      const form = await request.formData();
      const user = String(form.get("username") || "");
      const pass = String(form.get("password") || "");

      if (
        !(await safeEqual(user, env.LOGIN_USER)) ||
        !(await safeEqual(pass, env.LOGIN_PASS))
      ) {
        return html(loginPage("帳號或密碼錯誤"), 401);
      }

      const token = await makeToken(env.SESSION_SECRET, ip);

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${TTL}`,
          "Cache-Control": "no-store",
        },
      });
    }

    return new Response("Method Not Allowed", { status: 405 });
  }

  if (!(await validSession(request, env.SESSION_SECRET, ip))) {
    return redirect("/login");
  }

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set("Cache-Control", "private, no-store, max-age=0");
  out.headers.set("X-Content-Type-Options", "nosniff");
  return out;
}

function redirect(location) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      "Cache-Control": "no-store",
    },
  });
}

function html(body, status = 200) {
  return new Response(`<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VIA｜管理中心</title>
<style>
:root{
  color-scheme:dark;
  --bg:#081526;
  --bg2:#0e223a;
  --panel:rgba(17,38,62,.78);
  --border:rgba(151,184,221,.16);
  --text:#eef6ff;
  --muted:#8295aa;
  --accent:#3c7cff;
  --accent2:#51b8ff;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{
  min-height:100vh;
  display:grid;
  place-items:center;
  overflow:hidden;
  padding:24px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft JhengHei",sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at 22% 18%,rgba(45,104,180,.22),transparent 34%),
    radial-gradient(circle at 80% 72%,rgba(31,92,165,.13),transparent 38%),
    linear-gradient(135deg,var(--bg),var(--bg2));
}
body::before{
  content:"";
  position:fixed;
  width:460px;
  height:460px;
  border-radius:50%;
  left:-170px;
  bottom:-240px;
  background:rgba(50,116,210,.11);
  filter:blur(18px);
  pointer-events:none;
}
.card{
  position:relative;
  width:min(92vw,470px);
  padding:48px 38px 42px;
  border:1px solid rgba(120,170,225,.28);
  border-radius:28px;
  background:linear-gradient(160deg,rgba(22,49,79,.88),rgba(15,37,62,.82));
  box-shadow:
    0 30px 90px rgba(0,0,0,.34),
    inset 0 1px 0 rgba(255,255,255,.04);
  backdrop-filter:blur(24px);
  -webkit-backdrop-filter:blur(24px);
}
.brand{
  text-align:center;
  margin-bottom:34px;
}
.logo{
  font-size:58px;
  line-height:1;
  font-weight:500;
  letter-spacing:.20em;
  padding-left:.20em;
  color:#9bc2ff;
}
.sub{
  margin-top:14px;
  font-size:14px;
  letter-spacing:.24em;
  padding-left:.24em;
  color:#8ea2b8;
}
.field{
  display:flex;
  align-items:center;
  gap:12px;
  height:56px;
  margin-top:14px;
  padding:0 17px;
  border:1px solid rgba(151,184,221,.20);
  border-radius:14px;
  background:rgba(255,255,255,.035);
  transition:border-color .18s,background .18s,box-shadow .18s;
}
.field:focus-within{
  border-color:rgba(79,145,255,.56);
  background:rgba(255,255,255,.048);
  box-shadow:0 0 0 3px rgba(60,124,255,.08);
}
.icon{
  width:19px;
  height:19px;
  flex:0 0 19px;
  display:grid;
  place-items:center;
  color:#71879d;
}
.icon svg{
  width:19px;
  height:19px;
  fill:none;
  stroke:currentColor;
  stroke-width:1.8;
  stroke-linecap:round;
  stroke-linejoin:round;
}
input{
  width:100%;
  height:100%;
  padding:0;
  border:0;
  outline:0;
  background:transparent;
  color:var(--text);
  font-size:15px;
}
input::placeholder{color:#667b90}
button{
  width:100%;
  height:54px;
  margin-top:20px;
  border:0;
  border-radius:14px;
  cursor:pointer;
  color:#fff;
  font-size:14px;
  font-weight:700;
  letter-spacing:.04em;
  background:linear-gradient(100deg,#5d86ff 0%,#5c8dfb 52%,#58d9dc 100%);
  box-shadow:0 14px 30px rgba(47,111,225,.24);
  transition:transform .16s,filter .16s;
}
button:hover{filter:brightness(1.07)}
button:active{transform:translateY(1px)}
.err{
  margin:0 0 13px;
  padding:10px 12px;
  border:1px solid rgba(255,101,101,.22);
  border-radius:10px;
  color:#ff9b9b;
  background:rgba(255,72,72,.07);
  text-align:center;
  font-size:13px;
}
h2{
  margin:0 0 12px;
  text-align:center;
  font-size:20px;
}
.message{
  margin:0;
  text-align:center;
  color:var(--muted);
  font-size:13px;
}
@media(max-width:520px){
  body{padding:18px}
  .card{width:min(94vw,470px);padding:38px 24px 32px;border-radius:22px}
  .logo{font-size:46px}
}
</style>
</head>
<body>
<div class="card">${body}</div>
</body>
</html>`, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function loginPage(error) {
  return `
  <div class="brand">
    <div class="logo">VIA</div>
    <div class="sub">管理中心</div>
  </div>

  ${error ? `<div class="err">${esc(error)}</div>` : ""}

  <form method="POST" action="/login">
    <div class="field">
      <span class="icon" aria-hidden="true">
        <svg viewBox="0 0 24 24">
          <circle cx="12" cy="8" r="4"></circle>
          <path d="M5 19c1.8-3.1 5-4.5 7-4.5s5.2 1.4 7 4.5"></path>
        </svg>
      </span>
      <input
        name="username"
        placeholder="帳號"
        autocomplete="username"
        required
        autofocus
      >
    </div>

    <div class="field">
      <span class="icon" aria-hidden="true">
        <svg viewBox="0 0 24 24">
          <rect x="5" y="11" width="14" height="9" rx="2"></rect>
          <path d="M8 11V8a4 4 0 1 1 8 0v3"></path>
        </svg>
      </span>
      <input
        name="password"
        type="password"
        placeholder="密碼"
        autocomplete="current-password"
        required
      >
    </div>

    <button type="submit">登入 →</button>
  </form>`;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const p of raw.split(";")) {
    const i = p.indexOf("=");
    if (i > -1 && p.slice(0, i).trim() === name) {
      return p.slice(i + 1).trim();
    }
  }
  return "";
}

async function makeToken(secret, ip) {
  const payload = b64(
    new TextEncoder().encode(
      JSON.stringify({
        ip,
        exp: Math.floor(Date.now() / 1000) + TTL,
      })
    )
  );

  return `${payload}.${await sign(secret, payload)}`;
}

async function validSession(request, secret, ip) {
  const token = getCookie(request, COOKIE);
  const parts = token.split(".");

  if (parts.length !== 2) return false;
  if (!(await safeEqual(parts[1], await sign(secret, parts[0])))) return false;

  try {
    const data = JSON.parse(
      new TextDecoder().decode(unb64(parts[0]))
    );

    return (
      data.ip === ip &&
      Number.isFinite(data.exp) &&
      data.exp > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

async function sign(secret, value) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return b64(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, enc.encode(value))
    )
  );
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();

  const [aa, bb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(String(a))),
    crypto.subtle.digest("SHA-256", enc.encode(String(b))),
  ]);

  const x = new Uint8Array(aa);
  const y = new Uint8Array(bb);

  let d = 0;
  for (let i = 0; i < x.length; i++) {
    d |= x[i] ^ y[i];
  }

  return d === 0;
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);

  return btoa(s)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");

  while (s.length % 4) s += "=";

  const raw = atob(s);
  const out = new Uint8Array(raw.length);

  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }

  return out;
}

function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[c]));
}
