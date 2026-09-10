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
    return html(`<h2>此 IP 未授權</h2><p>目前來源 IP：${esc(ip || "無法取得")}</p>`, 403);
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

      if (!(await safeEqual(user, env.LOGIN_USER)) ||
          !(await safeEqual(pass, env.LOGIN_PASS))) {
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
    headers: { Location: location, "Cache-Control": "no-store" },
  });
}

function html(body, status = 200) {
  return new Response(`<!doctype html><html lang="zh-Hant"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>財務查詢餘額</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f7;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft JhengHei",sans-serif;color:#222}
.card{width:min(92vw,360px);background:#fff;border:1px solid #ddd;border-radius:14px;padding:24px}
h1,h2{text-align:center}label{display:block;margin:12px 0 6px;font-weight:700}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ccc;border-radius:8px}
button{width:100%;margin-top:18px;padding:10px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:700}
.err{color:#b91c1c;text-align:center;margin-bottom:10px}.note{text-align:center;color:#777;font-size:12px;margin-top:12px}
</style></head><body><div class="card">${body}</div></body></html>`, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function loginPage(error) {
  return `<h1>財務查詢餘額</h1>
${error ? `<div class="err">${esc(error)}</div>` : ""}
<form method="POST" action="/login">
<label>帳號</label><input name="username" autocomplete="username" required autofocus>
<label>密碼</label><input name="password" type="password" autocomplete="current-password" required>
<button type="submit">登入</button>
<div class="note">僅限授權 IP 使用</div>
</form>`;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const p of raw.split(";")) {
    const i = p.indexOf("=");
    if (i > -1 && p.slice(0, i).trim() === name) return p.slice(i + 1).trim();
  }
  return "";
}

async function makeToken(secret, ip) {
  const payload = b64(new TextEncoder().encode(JSON.stringify({
    ip,
    exp: Math.floor(Date.now() / 1000) + TTL,
  })));
  return `${payload}.${await sign(secret, payload)}`;
}

async function validSession(request, secret, ip) {
  const token = getCookie(request, COOKIE);
  const parts = token.split(".");
  if (parts.length !== 2) return false;

  if (!(await safeEqual(parts[1], await sign(secret, parts[0])))) return false;

  try {
    const data = JSON.parse(new TextDecoder().decode(unb64(parts[0])));
    return data.ip === ip &&
      Number.isFinite(data.exp) &&
      data.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function sign(secret, value) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  return b64(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value))));
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [aa, bb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(String(a))),
    crypto.subtle.digest("SHA-256", enc.encode(String(b))),
  ]);
  const x = new Uint8Array(aa), y = new Uint8Array(bb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function unb64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const raw = atob(s), out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function esc(v) {
  return String(v).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}
