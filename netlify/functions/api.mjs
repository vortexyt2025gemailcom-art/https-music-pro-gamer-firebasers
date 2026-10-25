import { getStore } from "@netlify/blobs";
import { randomBytes, pbkdf2Sync, timingSafeEqual } from "node:crypto";

const J = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const fail = (msg, status = 400) => J(status, { error: msg });
const hash = (pass, salt) => pbkdf2Sync(pass, salt, 100000, 32, "sha256").toString("hex");
const chatId = (a, b) => [a, b].sort().join("_");
const pad = n => String(n).padStart(15, "0");
const pub = u => ({ num: u.num, name: u.name, photo: u.photo || "", online: !!u.seen && Date.now() - u.seen < 60000 });
const PUBLIC = ["signup", "login", "logout"];
const num = x => String(x || "").replace(/\D/g, "");

export default async (req) => {
  if (req.method !== "POST") return fail("Método no permitido", 405);
  let b;
  try { b = await req.json(); } catch { return fail("Datos inválidos"); }

  const s = getStore({ name: "musicchat", consistency: "strong" });
  const get = k => s.get(k, { type: "json" });
  const put = (k, v) => s.setJSON(k, v);
  const list = async prefix => (await s.list({ prefix })).blobs.map(x => x.key);

  const token = /^[0-9a-f]{64}$/.test(b.token || "") ? b.token : "";
  const sess = token ? await get("sess/" + token) : null;
  const me = sess ? await get("user/" + sess.num) : null;

  if (!PUBLIC.includes(b.action) && !me) return fail("Tu sesión terminó. Inicia sesión otra vez.", 401);

  const session = async n => {
    const t = randomBytes(32).toString("hex");
    await put("sess/" + t, { num: n });
    return J(200, { token: t, me: pub(await get("user/" + n)) });
  };
  const markDelivered = async id => {
    for (const k of (await list("msg/" + id + "/")).sort().slice(-30)) {
      const m = await get(k);
      if (m && m.to === me.num && m.st < 2) { m.st = 2; await put(k, m); }
    }
  };

  switch (b.action) {
    case "signup": {
      const n = num(b.num), name = String(b.name || "").trim().slice(0, 40);
      const email = String(b.email || "").trim().toLowerCase(), pass = String(b.pass || "");
      if (n.length !== 15) return fail("El número de chat debe tener 15 dígitos");
      if (!name) return fail("Escribe el nombre que verán en el chat");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Correo no válido");
      if (pass.length < 6) return fail("El código debe tener mínimo 6 caracteres");
      if (await get("user/" + n)) return fail("Ese número ya está en uso. Inventa otro.");
      if (await get("email/" + email)) return fail("Ese correo ya tiene una cuenta");
      const salt = randomBytes(16).toString("hex");
      await put("user/" + n, { num: n, name, email, salt, hash: hash(pass, salt), photo: "", seen: 0 });
      await put("email/" + email, { num: n });
      return session(n);
    }
    case "login": {
      const email = String(b.email || "").trim().toLowerCase();
      const e = await get("email/" + email);
      const u = e ? await get("user/" + e.num) : null;
      if (!u) return fail("Correo o código incorrecto", 401);
      const ok = timingSafeEqual(Buffer.from(hash(String(b.pass || ""), u.salt), "hex"), Buffer.from(u.hash, "hex"));
      if (!ok) return fail("Correo o código incorrecto", 401);
      return session(u.num);
    }
    case "logout": {
      if (token) await s.delete("sess/" + token);
      return J(200, { ok: true });
    }
    case "me": {
      me.seen = Date.now();
      await put("user/" + me.num, me);
      return J(200, { me: pub(me) });
    }
    case "photo": {
      const x = String(b.photo || "");
      if (!x.startsWith("data:image/") || x.length > 400000) return fail("Foto no válida o muy grande");
      me.photo = x;
      await put("user/" + me.num, me);
      return J(200, { me: pub(me) });
    }
    case "find": {
      const n = num(b.num);
      if (n === me.num) return fail("Ese es tu propio número");
      const u = await get("user/" + n);
      if (!u) return fail("No se encontró ese número");
      return J(200, { profile: pub(u) });
    }
    case "accept": {
      const n = num(b.num);
      if (n === me.num || !(await get("user/" + n))) return fail("No se encontró ese número");
      for (const [o, p] of [[me.num, n], [n, me.num]]) {
        const k = "inbox/" + o + "/" + p;
        if (!(await get(k))) await put(k, { peer: p, last: "", lt: Date.now() });
      }
      return J(200, { ok: true });
    }
    case "chats": {
      const items = [];
      for (const k of await list("inbox/" + me.num + "/")) {
        const it = await get(k);
        if (it) items.push(it);
      }
      items.sort((a, b) => b.lt - a.lt);
      const out = [];
      for (const it of items) {
        await markDelivered(chatId(me.num, it.peer));
        const u = await get("user/" + it.peer);
        out.push({
          peer: it.peer,
          last: it.last,
          profile: u ? pub(u) : { num: it.peer, name: "Contacto", photo: "", online: false }
        });
      }
      return J(200, { chats: out });
    }
    case "messages": {
      const p = num(b.peer);
      if (!(await get("inbox/" + me.num + "/" + p))) return fail("Este chat no existe", 404);
      const id = chatId(me.num, p);
      const keys = (await list("msg/" + id + "/")).sort().slice(-100);
      const msgs = [];
      for (const k of keys) {
        const m = await get(k);
        if (!m) continue;
        if (m.to === me.num && m.st < 3) { m.st = 3; await put(k, m); }
        msgs.push(m);
      }
      const pu = await get("user/" + p);
      return J(200, {
        peer: pu ? pub(pu) : { num: p, name: "Contacto", photo: "", online: false },
        msgs
      });
    }
    case "send": {
      const p = num(b.to), k = b.k, x = String(b.x || "");
      if (!(await get("inbox/" + me.num + "/" + p))) return fail("Este chat no existe", 404);
      if (k === "t") { if (!x.trim() || x.length > 2000) return fail("Mensaje no válido"); }
      else if (k === "i") { if (!x.startsWith("data:image/") || x.length > 1.5e6) return fail("Foto no válida o muy grande"); }
      else if (k === "v") { if (!x.startsWith("data:video/") || x.length > 4.8e6) return fail("Video muy grande (máximo 3.5 MB)"); }
      else return fail("Tipo de mensaje no válido");
      const t = Date.now();
      await put("msg/" + chatId(me.num, p) + "/" + pad(t) + "-" + randomBytes(4).toString("hex"),
        { from: me.num, to: p, k, x, st: 1, t });
      const last = k === "t" ? x.slice(0, 40) : k === "i" ? "📷 Foto" : "🎥 Video";
      for (const [o, pe] of [[me.num, p], [p, me.num]]) {
        const r = await get("inbox/" + o + "/" + pe);
        if (r) { r.last = last; r.lt = t; await put("inbox/" + o + "/" + pe, r); }
      }
      return J(200, { ok: true });
    }
    default:
      return fail("Acción no válida");
  }
};
