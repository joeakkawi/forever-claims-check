// Forever claiming and the /forever command: black-box check against the deployed Forever service.
// Uses only what Mousekeeper already has (FOREVER_ORIGIN, FOREVER_SHARED_KEY). No Battle.net login needed:
// every check either stops before the Battle.net exchange or uses a deliberately invalid code.
//
//   FOREVER_ORIGIN=https://... FOREVER_SHARED_KEY=... node extras/forever-claims-check.mjs
//
// Side effects: creates a few short-lived login states for a test Discord id (all consumed or expiring in 10 min).
// Nothing is claimed. Output never includes the key, session tokens, the Forever address or login URLs, so it can be
// pasted as evidence.
import crypto from "node:crypto";

const ORIGIN = (process.env.FOREVER_ORIGIN || "").replace(/\/+$/, "");
const KEY = process.env.FOREVER_SHARED_KEY || "";
if (!ORIGIN.startsWith("https://") || !KEY) { console.error("Set FOREVER_ORIGIN (https) and FOREVER_SHARED_KEY."); process.exit(2); }

const TEST_SUB = "100000000000000001", OTHER_SUB = "100000000000000002";
const hmac = m => crypto.createHmac("sha256", KEY).update(m).digest("base64url");
let failed = 0;
const check = (name, ok, detail = "") => { if (!ok) failed++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`); };

// A member session on the Forever site, exactly as Mousekeeper's /forever page creates one (signed pass).
async function session(sub) {
  const iat = Math.floor(Date.now() / 1000);
  const body = Buffer.from(JSON.stringify({ sub, name: "Claim check", iat, exp: iat + 120, nonce: crypto.randomUUID() })).toString("base64url");
  const html = await (await fetch(`${ORIGIN}/mk-login?pass=${encodeURIComponent(`${body}.${hmac(body)}`)}`)).text();
  const token = /const TOKEN = "([^"]+)"/.exec(html)?.[1];
  if (!token) throw new Error("Could not open a session on the Forever site (check FOREVER_ORIGIN and FOREVER_SHARED_KEY).");
  return token;
}
async function startClaim(sub) {
  const token = await session(sub);
  const r = await fetch(`${ORIGIN}/api/claim/start`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  const j = await r.json();
  if (!j.url) throw new Error(`Claim start failed (HTTP ${r.status}${j.error ? `: ${String(j.error).slice(0, 80)}` : ""})`);
  const u = new URL(j.url);
  return { state: u.searchParams.get("state"), redirect: u.searchParams.get("redirect_uri"), host: u.host };
}
// The callback exactly as Mousekeeper's /forever/bnet/callback sends it.
async function callback(state, sub, params = {}, ts = String(Date.now())) {
  const q = new URLSearchParams({ state, ...params });
  const r = await fetch(`${ORIGIN}/bnet/callback?${q}`, { headers: { "x-mk-ts": ts, "x-mk-sub": sub, "x-mk-sig": hmac(`bnet:${state}:${sub}:${ts}`) } });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

console.log(`Forever claims check against the configured FOREVER_ORIGIN, ${new Date().toISOString()}\n`);

const s0 = await startClaim(TEST_SUB);
check("Claim start returns a Battle.net login with Mousekeeper's return address", s0.host === "oauth.battle.net" && /\/forever\/bnet\/callback$/.test(s0.redirect || ""), s0.redirect ? new URL(s0.redirect).pathname : "missing");

// Single use under concurrency: 20 simultaneous callbacks for one state. The invalid code means the one that
// wins the state stops at the Battle.net exchange ("failed"); every other one must find the state gone ("expired").
const race = await startClaim(TEST_SUB);
const results = await Promise.all(Array.from({ length: 20 }, () => callback(race.state, TEST_SUB, { code: "invalid-test-code" })));
const codes = results.map(r => r.body.code ?? `HTTP ${r.status}`);
const tally = codes.reduce((t, c) => ((t[c] = (t[c] || 0) + 1), t), {});
// The winner consumed the state and was then refused by Battle.net (invalid code): "failed". Every other: "expired".
check("20 simultaneous callbacks: exactly 1 'failed' (state consumed) and 19 'expired'", tally.failed === 1 && tally.expired === 19 && Object.keys(tally).length === 2, JSON.stringify(tally));
const again = await callback(race.state, TEST_SUB, { code: "invalid-test-code" });
check("Same login replayed afterwards is refused", again.body.code === "expired", again.body.code);

const s1 = await startClaim(TEST_SUB);
const wrong = await callback(s1.state, OTHER_SUB, { code: "invalid-test-code" });
check("Another member can't finish this login", wrong.status === 403 && wrong.body.code === "mismatch", wrong.body.code);
const after = await callback(s1.state, TEST_SUB, { code: "invalid-test-code" });
check("Login is used up even after a refused attempt", after.body.code === "expired", after.body.code);

const s2 = await startClaim(TEST_SUB);
const stale = await callback(s2.state, TEST_SUB, { code: "x" }, String(Date.now() - 90_000));
check("90 second old signature refused", stale.status === 403 && stale.body.code === "badsig", stale.body.code);
const r = await fetch(`${ORIGIN}/bnet/callback?state=${s2.state}&code=x`);
check("Unsigned callback refused", r.status === 403);
const forged = await fetch(`${ORIGIN}/bnet/callback?state=${s2.state}&code=x`, { headers: { "x-mk-ts": String(Date.now()), "x-mk-sub": TEST_SUB, "x-mk-sig": hmac("something else") } });
check("Wrongly signed callback refused", forged.status === 403);
const unknown = await callback(crypto.randomBytes(32).toString("hex"), TEST_SUB, { code: "x" });
check("Unknown login state refused", unknown.body.code === "expired", unknown.body.code);
const cancel = await callback(s2.state, TEST_SUB, { error: "denied" });
check("Member pressing Cancel on Battle.net", cancel.body.code === "denied", cancel.body.code);

// Public profiles: no signature, a deliberately wrong signature, and a correct signature for a non-member.
const slug = "this-is-not-a-member";
const p1 = await fetch(`${ORIGIN}/public/c/${slug}.json`);
check("Public profile: request with no signature headers refused (404)", p1.status === 404, `HTTP ${p1.status}`);
const pts = String(Date.now());
const p2 = await fetch(`${ORIGIN}/public/c/${slug}.json`, { headers: { "x-mk-ts": pts, "x-mk-sig": hmac(`public:another-name:${pts}`) } });
check("Public profile: request with a wrong signature refused (404)", p2.status === 404, `HTTP ${p2.status}`);
const p3 = await fetch(`${ORIGIN}/public/c/${slug}.json`, { headers: { "x-mk-ts": pts, "x-mk-sig": hmac(`public:${slug}:${pts}`) } });
const p3body = await p3.json().catch(() => ({}));
check("Public profile: correctly signed request for a non-member refused by the roster check (404)", p3.status === 404 && p3body.error === "not_found", `HTTP ${p3.status} ${p3body.error || ""}`);


// Discord /forever command endpoints. None of these make a card or start a cooldown: each is refused before that.
const bot = async (path, sub, msg, ts = String(Date.now()), sig) => {
  const headers = sub == null ? {} : { "x-mk-ts": ts, "x-mk-sub": sub, "x-mk-sig": sig ?? hmac(msg.replace("{ts}", ts)) };
  const r = await fetch(`${ORIGIN}${path}`, { headers });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const b1 = await bot("/bot/v1/characters", null);
check("/forever command, list: request with no signature headers refused (401)", b1.status === 401, `HTTP ${b1.status}`);
const b2 = await bot("/bot/v1/characters", TEST_SUB, `bot-chars:${OTHER_SUB}:{ts}`);
check("/forever command, list: signature made for another Discord user refused (401)", b2.status === 401, `HTTP ${b2.status}`);
const b3 = await bot("/bot/v1/characters", TEST_SUB, `bot-chars:${TEST_SUB}:{ts}`);
check("/forever command, list: correctly signed request for a member with no claims returns an empty list", b3.status === 200 && Array.isArray(b3.body.characters) && b3.body.characters.length === 0, `HTTP ${b3.status}, ${b3.body.characters?.length ?? "?"} characters`);
// A real guild character, read the way a logged-in member's page reads it.
const rosterId = await (async () => { const t = await session(TEST_SUB); const d = await (await fetch(`${ORIGIN}/api/data`, { headers: { Authorization: `Bearer ${t}` } })).json(); return d.roster?.[0]?.id; })();
const b4 = await bot(`/bot/v1/summary/${rosterId}.png`, TEST_SUB, `bot-summary:${rosterId}:${TEST_SUB}:{ts}`, String(Date.now() - 90000));
check("/forever command, card: 90 second old signature refused (401)", b4.status === 401, `HTTP ${b4.status}`);
const b5 = await bot(`/bot/v1/summary/${rosterId}.png`, TEST_SUB, `bot-summary:${rosterId}:${TEST_SUB}:{ts}`);
check("/forever command, card: correctly signed request for a guild character this user hasn't claimed refused (403)", b5.status === 403 && b5.body.error === "not_yours", `HTTP ${b5.status} ${b5.body.error || ""}`);
const b6 = await bot("/bot/v1/summary/1.png", TEST_SUB, `bot-summary:1:${TEST_SUB}:{ts}`);
check("/forever command, card: character outside the guild roster refused (404)", b6.status === 404 && b6.body.error === "not_found", `HTTP ${b6.status} ${b6.body.error || ""}`);

console.log(`\n${failed ? `${failed} FAILED` : "All checks passed"}  (exit code ${failed ? 1 : 0})`);
process.exit(failed ? 1 : 0);
