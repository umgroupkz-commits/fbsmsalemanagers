// ═══════════════════════════════════════════════════════════
// FBSM — Supabase Edge Function (замена Google Apps Script)
// Повторяет тот же набор действий (action), чтобы фронтенд
// менялся минимально — только адрес сервера.
// ═══════════════════════════════════════════════════════════

import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
// URL старого Apps Script — используется ТОЛЬКО для получения факта
// по магазинам из второй таблицы (отчёты управляющих), и только когда
// пользователь явно нажимает "Обновить данные".
const APPS_SCRIPT_URL = Deno.env.get("APPS_SCRIPT_URL")!;

const sb = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

const SHOP_MAP: Record<string, string> = {
  "Караганда": "ГрандСтор (Караганда)",
  "Алматы": "Атакент (Алматы)",
  "Асфендиярова": "Асф. (Астана)",
  "Манаса": "Манаса (Астана)",
  "Республика": "Респ. (Астана)",
};
const SHOPS = Object.keys(SHOP_MAP);

// ═══════════════════════════════════════════════════════════
// ЭТАП 1: ВХОД С ПРОВЕРКОЙ ПАРОЛЯ НА СЕРВЕРЕ
// -----------------------------------------------------------
// Раньше пароль сверялся в браузере, а getUsers отдавал поле pass
// всем подряд — любой сотрудник видел пароль администратора.
//
// Здесь только НОВЫЙ метод login. Старое поведение не тронуто:
// пока фронтенд его не вызывает, ничего не меняется. Отключение
// выдачи паролей — следующим этапом, после проверки входа.
//
// Токен подписан HMAC на служебном ключе, который и так есть в
// окружении функции. Отдельная таблица сессий не нужна: токен
// самодостаточен и протухает сам.
// ═══════════════════════════════════════════════════════════

const TOKEN_HOURS = 12;

function b64url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s: string) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(s + "=".repeat((4 - s.length % 4) % 4)), (c) => c.charCodeAt(0));
}
async function hmac(payload: string) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(SERVICE_ROLE_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64url(new Uint8Array(sig));
}
async function makeToken(uid: string, role: string, shop: string | null) {
  const body = b64url(new TextEncoder().encode(JSON.stringify({
    uid, role, shop, exp: Date.now() + TOKEN_HOURS * 3600 * 1000,
  })));
  return body + "." + await hmac(body);
}
// Возвращает данные из токена или null. null — значит подписи нет,
// она не сходится или срок вышел.
async function readToken(token: string | null | undefined) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  if (sig !== await hmac(body)) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(unb64url(body)));
    if (!data.exp || data.exp < Date.now()) return null;
    return data as { uid: string; role: string; shop: string | null; exp: number };
  } catch { return null; }
}

// Сравнение, не зависящее от длины совпадающего префикса.
function sameSecret(a: string, b: string) {
  const x = String(a ?? ""), y = String(b ?? "");
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

async function login(body: any) {
  const { data, error } = await sb.from("users").select("*")
    .eq("id", body.id).is("deleted_at", null).maybeSingle();
  if (error) throw error;
  // Один и тот же ответ и на несуществующего пользователя, и на
  // неверный пароль — чтобы нельзя было перебором узнать, кто есть.
  if (!data || !sameSecret(data.pass, body.pass)) {
    return { ok: false, reason: "Неверное имя или пароль" };
  }
  const { pass: _drop, ...safe } = data as any;
  return { ok: true, token: await makeToken(data.id, data.role, data.shop), user: safe };
}

// Проверка живого токена — понадобится на следующем этапе.
async function whoami(body: any) {
  const t = await readToken(body.token);
  return t ? { ok: true, uid: t.uid, role: t.role, shop: t.shop } : { ok: false };
}


// ═══════════════════════════════════════════════════════════
// ЭТАП 2: ПРОВЕРКА ПРАВ НА СЕРВЕРЕ
// -----------------------------------------------------------
// Раньше роль проверялась только в браузере. Достаточно было
// выполнить в консоли CU.role='admin' — и открывались чужие
// зарплаты, параметры расчёта и удаление сотрудников. Сервер
// отвечал всем одинаково.
//
// Теперь каждый запрос приходит с токеном, выданным при входе.
// Сервер сам определяет, кто спрашивает, и решает, можно ли.
// ═══════════════════════════════════════════════════════════

// Работают без входа: список имён для формы входа, сам вход,
// параметры сетки (нужны до входа) и ночное обновление по расписанию.
const PUBLIC_ACTIONS = new Set(["login", "whoami", "getUsers", "getParams", "nightlyRefresh"]);

// Кому какое действие доступно. Не перечисленные здесь действия
// доступны любому вошедшему.
const ROLE_RULES: Record<string, string[]> = {
  addUser:         ["admin", "manager"],
  updateUser:      ["admin", "manager"],
  deleteUser:      ["admin", "manager"],
  restoreUser:     ["admin"],
  hardDeleteUser:  ["admin"],
  getDeletedUsers: ["admin"],
  saveParams:      ["admin"],
  saveMgrParams:   ["admin"],
  savePlan:        ["admin"],
  saveAdjustment:  ["admin", "accountant", "manager"],
  getAdjustment:   ["admin", "accountant", "manager"],
};

class AuthError extends Error {}

// Управляющий распоряжается только продавцами своего магазина.
// Проверяем по данным из базы, а не по тому, что прислал клиент.
async function assertCanTouchUser(auth: any, targetId: string) {
  if (auth.role === "admin") return;
  if (auth.role !== "manager") throw new AuthError("Недостаточно прав");
  const { data } = await sb.from("users").select("id,role,shop").eq("id", targetId).maybeSingle();
  if (!data) throw new AuthError("Сотрудник не найден");
  if (data.role !== "seller" || data.shop !== auth.shop) {
    throw new AuthError("Можно менять только продавцов своего магазина");
  }
}

// Кто вправе трогать продажи конкретного сотрудника.
async function assertCanTouchSales(auth: any, targetUid: string) {
  if (auth.role === "admin" || auth.role === "accountant") return;
  if (auth.role === "seller") {
    if (String(targetUid) !== String(auth.uid)) throw new AuthError("Можно вводить только свои продажи");
    return;
  }
  if (auth.role === "manager") {
    const { data } = await sb.from("users").select("id,shop").eq("id", targetUid).maybeSingle();
    if (!data || data.shop !== auth.shop) throw new AuthError("Только сотрудники своего магазина");
    return;
  }
  throw new AuthError("Недостаточно прав");
}

// Проверки, зависящие от содержимого запроса, а не только от роли.
async function guardAction(action: string, body: any, auth: any) {
  if (ROLE_RULES[action] && !ROLE_RULES[action].includes(auth.role)) {
    throw new AuthError("Недостаточно прав для действия: " + action);
  }
  switch (action) {
    case "addUser":
      if (auth.role === "manager" && (body.role !== "seller" || body.shop !== auth.shop)) {
        throw new AuthError("Можно заводить только продавцов своего магазина");
      }
      break;
    case "updateUser":
      await assertCanTouchUser(auth, body.id);
      // Управляющий не может поменять роль или магазин — иначе увёл бы
      // сотрудника себе или выдал ему права администратора.
      if (auth.role === "manager" && (body.role !== "seller" || body.shop !== auth.shop)) {
        throw new AuthError("Управляющий не меняет роль и магазин");
      }
      break;
    case "deleteUser":
      // Здесь клиент присылает только id — роль и магазин проверяем
      // по базе внутри assertCanTouchUser.
      await assertCanTouchUser(auth, body.id);
      break;
    case "saveSale":
    case "deleteSale":
      await assertCanTouchSales(auth, body.uid);
      break;
    case "getSales":
    case "getBundle":
      // Продавец видит только свои продажи, что бы он ни прислал.
      if (auth.role === "seller") body.uid = auth.uid;
      break;
    case "saveAdjustment":
    case "getAdjustment":
      break;
  }
}

// ── USERS ──
// Единая функция чтения сотрудников: includeDeleted=false — активные
// (для входа и обычных списков), true — только "мягко удалённые"
// (для раздела восстановления). Раньше это были два почти одинаковых
// запроса — оставлена только разница в фильтре.
async function fetchUsers(includeDeleted: boolean) {
  // Поле pass НЕ выбираем. Раньше здесь стоял select("*"), и пароли всех
  // сотрудников уходили в браузер каждому, кто открыл страницу: продавец
  // видел пароль администратора через F12. Пароль нужен только методу
  // login, он читает его отдельно и наружу не отдаёт.
  let q = sb.from("users").select("id,name,shop,role,created_at,deleted_at");
  q = includeDeleted ? q.not("deleted_at", "is", null) : q.is("deleted_at", null);
  const { data, error } = await q;
  if (error) throw error;
  return data;
}
async function getUsers() {
  return fetchUsers(false);
}
async function getDeletedUsers() {
  return fetchUsers(true);
}
async function addUser(body: any) {
  const id = "u" + Date.now();
  const { error } = await sb.from("users").insert({
    id, name: body.name, shop: body.shop, role: body.role, pass: body.pass,
  });
  if (error) throw error;
  return { ok: true, id };
}
async function updateUser(body: any) {
  const patch: any = { name: body.name, shop: body.shop, role: body.role };
  // Пароль меняем, только если его действительно ввели. Раньше клиент
  // присылал сюда старый пароль, вычитанный из getUsers; теперь getUsers
  // его не отдаёт, и без этой проверки пароль затёрся бы пустым.
  if (body.pass !== undefined && body.pass !== null && body.pass !== "") {
    patch.pass = body.pass;
  }
  const { error } = await sb.from("users").update(patch).eq("id", body.id);
  if (error) throw error;
  return { ok: true };
}
async function deleteUser(body: any) {
  // Мягкое удаление — данные и вся история продаж сохраняются,
  // сотрудник просто скрывается из активных списков.
  const { error } = await sb.from("users").update({
    deleted_at: new Date().toISOString(),
  }).eq("id", body.id);
  if (error) throw error;
  return { ok: true };
}
async function restoreUser(body: any) {
  const { error } = await sb.from("users").update({ deleted_at: null }).eq("id", body.id);
  if (error) throw error;
  return { ok: true };
}
async function hardDeleteUser(body: any) {
  // Безвозвратное удаление — разрешено ТОЛЬКО для уже "мягко удалённых"
  // сотрудников (защита от случайного окончательного удаления активного
  // человека в один клик). История продаж/планов этого uid НЕ трогается —
  // остаётся в базе как исторические данные, привязанные к id.
  const { data: existing, error: checkErr } = await sb.from("users")
    .select("id, deleted_at").eq("id", body.id).maybeSingle();
  if (checkErr) throw checkErr;
  if (!existing || !existing.deleted_at) {
    throw new Error("Окончательное удаление доступно только для уже удалённых сотрудников");
  }
  const { error } = await sb.from("users").delete().eq("id", body.id);
  if (error) throw error;
  return { ok: true };
}

// ── PARAMS ──
// Общий список ключей сетки — используется и для продавцов (без префикса),
// и для управляющих (с префиксом mgr_). Раньше был продублирован в двух
// функциях сохранения — теперь одно место истины.
const PARAM_KEYS = ["rate","shifts","base","p80","p100","p140","bMag","bKpi","avgNorm","uptNorm"];

// prefix='' — параметры продавцов, prefix='mgr_' — параметры управляющих.
async function fetchParams(prefix: string) {
  let q = sb.from("params").select("*");
  q = prefix ? q.like("key", prefix + "%") : q;
  const { data, error } = await q;
  if (error) throw error;
  const result: Record<string, any> = {};
  (data || []).forEach((r: any) => {
    // Без префикса нужно ещё исключить чужие (mgr_*) ключи, иначе они
    // попадут в общую выборку вместе с параметрами продавцов.
    if (!prefix && r.key.startsWith("mgr_")) return;
    const key = prefix ? r.key.slice(prefix.length) : r.key;
    const num = parseFloat(r.value);
    result[key] = isNaN(num) ? r.value : num;
  });
  return result;
}
async function saveParamsWithPrefix(prefix: string, body: any) {
  for (const k of PARAM_KEYS) {
    if (body[k] !== undefined) {
      const { error } = await sb.from("params").upsert({ key: prefix + k, value: String(body[k]) });
      if (error) throw error;
    }
  }
  return { ok: true };
}
async function getParams() {
  return fetchParams("");
}
async function saveParams(body: any) {
  return saveParamsWithPrefix("", body);
}
async function getMgrParams() {
  return fetchParams("mgr_");
}
async function saveMgrParams(body: any) {
  return saveParamsWithPrefix("mgr_", body);
}

// ── PLANS ──
async function getPlans(body: any) {
  let q = sb.from("plans").select("*");
  if (body.uid) q = q.eq("uid", body.uid);
  if (body.mk)  q = q.eq("mk", body.mk);
  const { data, error } = await q;
  if (error) throw error;
  return data;
}
async function savePlan(body: any) {
  const mk = String(body.mk).slice(0, 7);
  const key = body.uid + "_" + mk;
  const { error } = await sb.from("plans").upsert({
    key, uid: body.uid, mk, amount: body.amount,
  });
  if (error) throw error;
  return { ok: true };
}

// ── SALES ──
async function getSales(body: any) {
  let q = sb.from("sales").select("*");
  if (body.uid) q = q.eq("uid", body.uid);
  if (body.mk)  q = q.like("date", body.mk + "%");
  const { data, error } = await q;
  if (error) throw error;
  return data;
}
async function saveSale(body: any) {
  const date = String(body.date).slice(0, 10);
  const key = body.uid + "_" + date;
  const { error } = await sb.from("sales").upsert({
    key, uid: body.uid, date,
    sales: body.sales || 0, checks: body.checks || 0,
    units: body.units || 0, returns: body.returns || 0,
    // Откуда запись: 'manual' — внёс человек, '1c' — приехало из обмена.
    // Нужно, чтобы отличить день, где продавец реально работал и просто
    // не было продаж, от дня, где 1С отнесла к нему чужой возврат.
    source: body.source || "manual",
  });
  if (error) throw error;
  return { ok: true };
}
async function deleteSaleEntry(body: any) {
  const key = body.uid + "_" + body.date;
  const { error } = await sb.from("sales").delete().eq("key", key);
  if (error) throw error;
  return { ok: true };
}

// ── ФАКТ ПО МАГАЗИНАМ (мост к старому Apps Script) ──
// Работает как раньше: сохранённое значение хранится ПОСТОЯННО и
// обновляется, только когда явно передан forceRefresh=true (то есть
// когда пользователь нажал кнопку "Обновить данные").
async function getReportFactFromCacheOrBridge(mk: string, forceRefresh: boolean) {
  if (!forceRefresh) {
    const { data } = await sb.from("shop_fact_cache").select("*").eq("mk", mk).maybeSingle();
    if (data) return { facts: data.data, updatedAt: data.updated_at };
  }

  // Идём в старый Apps Script за свежими данными
  let facts: Record<string, number> = {};
  try {
    const url = APPS_SCRIPT_URL + "?action=getReportFactOnly&mk=" + encodeURIComponent(mk) +
                "&forceRefresh=1";
    const resp = await fetch(url, { redirect: "follow" });
    facts = await resp.json();
  } catch (e) {
    console.error("Bridge to Apps Script failed:", e);
    // Если мост недоступен — отдаём то, что было закэшировано раньше (если было)
    const { data } = await sb.from("shop_fact_cache").select("*").eq("mk", mk).maybeSingle();
    if (data) return { facts: data.data, updatedAt: data.updated_at };
    return { facts: {}, updatedAt: null };
  }

  const nowIso = new Date().toISOString();
  await sb.from("shop_fact_cache").upsert({ mk, data: facts, updated_at: nowIso });
  return { facts, updatedAt: nowIso };
}

async function getShopStats(body: any) {
  const mk = (body.mk || "").slice(0, 7);
  const forceRefresh = !!body.forceRefresh;

  const [{ data: sales }, { data: users }, { data: plans }] = await Promise.all([
    sb.from("sales").select("*").like("date", mk + "%"),
    sb.from("users").select("*").eq("role", "seller"),
    sb.from("plans").select("*"),
  ]);

  const { facts: reportFacts, updatedAt } = await getReportFactFromCacheOrBridge(mk, forceRefresh);

  const result: Record<string, any> = {};
  for (const shop of SHOPS) {
    const shopSellerIds = (users || []).filter((u: any) => u.shop === shop).map((u: any) => u.id);
    const shopSales = (sales || []).filter((s: any) => shopSellerIds.includes(String(s.uid)));
    let consultantFact = 0;
    shopSales.forEach((s: any) => consultantFact += parseFloat(s.sales) || 0);

    const reportName = SHOP_MAP[shop] || shop;
    const totalFact = (reportFacts as any)[reportName] || consultantFact;
    const otherFact = Math.max(0, totalFact - consultantFact);

    const planKey = "shop_" + shop;
    const planRow = (plans || []).find((p: any) => p.uid === planKey && String(p.mk).slice(0,7) === mk);
    const planAmt = planRow ? parseFloat(planRow.amount) || 0 : 0;

    result[shop] = {
      fact: totalFact,
      consultants: consultantFact,
      other: otherFact,
      plan: planAmt,
      pct: planAmt > 0 ? totalFact / planAmt : 0,
      hasReportData: !!(reportFacts as any)[reportName],
    };
  }

  return { shops: result, updatedAt };
}

// ── ОБЪЕДИНЁННЫЙ ЗАПРОС (как раньше — одна функция вместо многих) ──
// ── АВТОМАТИЧЕСКОЕ НОЧНОЕ ОБНОВЛЕНИЕ ──
// Вызывается по расписанию (pg_cron) раз в сутки. Принудительно
// обновляет факт по магазинам за текущий месяц (и предыдущий — на
// случай, если отчёт за последний день месяца внесли поздно вечером).
async function nightlyRefresh() {
  const now = new Date();
  const curMk = now.getUTCFullYear() + "-" + String(now.getUTCMonth() + 1).padStart(2, "0");
  const prevDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const prevMk = prevDate.getUTCFullYear() + "-" + String(prevDate.getUTCMonth() + 1).padStart(2, "0");

  const results: Record<string, any> = {};
  for (const mk of [curMk, prevMk]) {
    try {
      const { facts, updatedAt } = await getReportFactFromCacheOrBridge(mk, true);
      results[mk] = { ok: true, shopsCount: Object.keys(facts).length, updatedAt };
    } catch (e) {
      results[mk] = { ok: false, error: (e as Error).message };
    }
  }
  return { refreshed: results };
}

// ── КОРРЕКТИРОВКИ ПЕРЕД НАЧИСЛЕНИЕМ (аванс, пенсия, штрафы, корр. сумма) ──
async function getAdjustment(body: any) {
  const key = body.uid + "_" + body.mk;
  const { data, error } = await sb.from("adjustments").select("*").eq("key", key).maybeSingle();
  if (error) throw error;
  return data || { uid: body.uid, mk: body.mk, corrected_sales: null, advance: 0, pension: 0, fines: 0, bonus: 0, bonus_note: null };
}
async function getAdjustmentsForMonth(body: any) {
  const { data, error } = await sb.from("adjustments").select("*").eq("mk", body.mk);
  if (error) throw error;
  return data || [];
}
async function saveAdjustment(body: any) {
  const key = body.uid + "_" + body.mk;
  const { error } = await sb.from("adjustments").upsert({
    key, uid: body.uid, mk: body.mk,
    corrected_sales: body.correctedSales === null || body.correctedSales === "" ? null : parseFloat(body.correctedSales),
    advance: body.advance || 0,
    pension: body.pension || 0,
    fines: body.fines || 0,
    // Разовая премия — в отличие от штрафов, прибавляется к выплате.
    // Обоснование обязательно к заполнению на стороне программы.
    bonus: body.bonus || 0,
    bonus_note: body.bonusNote || null,
  });
  if (error) throw error;
  return { ok: true };
}

async function getBundle(body: any) {
  const uid = body.uid || null;
  const mk = body.mk || "";

  const salesBody: any = {};
  if (uid) salesBody.uid = uid;
  if (mk) salesBody.mk = mk;

  const [sales, plans, params] = await Promise.all([
    getSales(salesBody),
    getPlans({}),
    getParams(),
  ]);

  const result: any = { sales, plans, params };

  if (body.needShopStats) {
    const stats = await getShopStats({ mk, forceRefresh: !!body.forceRefresh });
    result.shopStats = stats.shops;
    result.shopStatsUpdatedAt = stats.updatedAt;
  }
  if (body.needMgrParams) {
    result.mgrParams = await getMgrParams();
  }
  if (body.needAdjustments) {
    result.adjustments = await getAdjustmentsForMonth({ mk });
  }

  return result;
}

// ── РОУТЕР ──
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS_HEADERS });
  }

  try {
    let action: string;
    let body: any;

    if (req.method === "GET") {
      const url = new URL(req.url);
      action = url.searchParams.get("action") || "";
      body = Object.fromEntries(url.searchParams.entries());
    } else {
      body = await req.json();
      action = body.action;
    }

    // ── ПРОВЕРКА ПРАВ ──
    if (!PUBLIC_ACTIONS.has(action)) {
      const auth = await readToken(body.token);
      if (!auth) {
        return json({ error: "Сессия истекла", authError: true }, 401);
      }
      await guardAction(action, body, auth);
    }

    let result;
    switch (action) {
      case "login":          result = await login(body);          break;
      case "whoami":         result = await whoami(body);         break;
      case "getUsers":       result = await getUsers();           break;
      case "addUser":        result = await addUser(body);        break;
      case "updateUser":     result = await updateUser(body);     break;
      case "deleteUser":     result = await deleteUser(body);     break;
      case "restoreUser":    result = await restoreUser(body);    break;
      case "hardDeleteUser": result = await hardDeleteUser(body); break;
      case "getDeletedUsers": result = await getDeletedUsers();   break;
      case "getParams":      result = await getParams();          break;
      case "saveParams":     result = await saveParams(body);     break;
      case "getMgrParams":   result = await getMgrParams();       break;
      case "saveMgrParams":  result = await saveMgrParams(body);  break;
      case "getPlans":       result = await getPlans(body);       break;
      case "savePlan":       result = await savePlan(body);       break;
      case "getSales":       result = await getSales(body);       break;
      case "saveSale":       result = await saveSale(body);       break;
      case "deleteSale":     result = await deleteSaleEntry(body);break;
      case "getShopStats": {
        const stats = await getShopStats(body);
        result = stats.shops;
        break;
      }
      case "getBundle":      result = await getBundle(body);      break;
      case "nightlyRefresh": result = await nightlyRefresh();     break;
      case "getAdjustment":  result = await getAdjustment(body);  break;
      case "saveAdjustment": result = await saveAdjustment(body); break;
      default:
        return json({ error: "Unknown action: " + action }, 400);
    }

    return json(result);
  } catch (e) {
    if (e instanceof AuthError) {
      return json({ error: e.message }, 403);
    }
    console.error(e);
    return json({ error: (e as Error).message || String(e) }, 500);
  }
});
