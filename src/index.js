// src/index.js
//
// Requests matching a real file in ./public are served automatically by
// Cloudflare as static assets -- this fetch() handler only ever runs for
// paths that don't match a file, which in practice means our /api/* routes.
//
// Login is a single 6-digit PIN, unique per person, looked up directly in
// the staff directory -- no email, no domain, no third-party service.
//   1. POST /api/login   { pin }   -> verifies the PIN, sets a session cookie
//   2. GET  /api/my-data            -> returns this person's scoped data
//   3. POST /api/logout              -> clears the session

const SESSION_COOKIE = 'reslife_session';
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // session lasts 30 days

// Basic brute-force protection: a 6-digit PIN has 900,000 possible values
// (100000-999999), so unthrottled guessing is still worth capping. This
// limits attempts per source IP within a rolling window.
const MAX_ATTEMPTS = 10;
const ATTEMPT_WINDOW_SECONDS = 10 * 60; // 10 minutes
const LOCKOUT_SECONDS = 15 * 60;        // lock this IP out for 15 minutes once tripped

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }
    if (url.pathname === '/api/my-data' && request.method === 'GET') {
      return handleMyData(request, env);
    }
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      return handleLogout(request);
    }

    return json({ error: 'Not found' }, 404);
  },
};

// ── STEP 1: verify the PIN, start a session ────
async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const lockoutKey = `lockout:${ip}`;
  if (await env.RESLIFE_DATA.get(lockoutKey)) {
    return json({ error: 'Too many attempts. Try again in a few minutes.' }, 429);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid request' }, 400); }

  const pin = String(body.pin || '').trim();
  if (!/^\d{6}$/.test(pin)) {
    return json({ error: 'Enter your 6-digit PIN.' }, 400);
  }

  const raw = await env.RESLIFE_DATA.get('latest', { type: 'json' });
  if (!raw) return json({ error: 'No data available yet.' }, 503);

  const dir = raw.staff_directory || {};
  const entry = dir[pin];

  if (!entry) {
    // Wrong PIN -- count this attempt against the IP's rolling window.
    const attemptsKey = `attempts:${ip}`;
    const current = parseInt((await env.RESLIFE_DATA.get(attemptsKey)) || '0', 10);
    const next = current + 1;
    await env.RESLIFE_DATA.put(attemptsKey, String(next), { expirationTtl: ATTEMPT_WINDOW_SECONDS });
    if (next >= MAX_ATTEMPTS) {
      await env.RESLIFE_DATA.put(lockoutKey, '1', { expirationTtl: LOCKOUT_SECONDS });
      return json({ error: 'Too many incorrect attempts. Try again in 15 minutes.' }, 429);
    }
    return json({ error: 'Incorrect PIN.' }, 401);
  }

  // Correct PIN -- start a session. Admins log in with just their personal
  // PIN like everyone else; there is no separate admin access code.
  const token = crypto.randomUUID() + crypto.randomUUID(); // long, unguessable
  await env.RESLIFE_DATA.put(`session:${token}`, JSON.stringify(entry), {
    expirationTtl: SESSION_TTL_SECONDS,
  });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append(
    'Set-Cookie',
    `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`
  );
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// ── STEP 2: return this person's scoped data ───
async function handleMyData(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return json({ error: 'not_authenticated' }, 401);

  const sessionRaw = await env.RESLIFE_DATA.get(`session:${token}`);
  if (!sessionRaw) return json({ error: 'session_expired' }, 401);
  const entry = JSON.parse(sessionRaw); // { name, email, role }

  const raw = await env.RESLIFE_DATA.get('latest', { type: 'json' });
  if (!raw) return json({ error: 'no_data' }, 503);

  const scoped = buildScopedData(raw, entry);
  // Each person only ever receives their OWN personal up-eval link.
  const myLink = (raw.up_eval_links || {})[String(entry.name || '').toLowerCase().replace(/\s+/g, ' ').trim()];
  if (myLink && scoped && typeof scoped === 'object' && entry.role && String(entry.role).toLowerCase() !== 'admin') {
    scoped.my_up_eval_link = myLink;
  }
  // Each person only ever receives their OWN down-eval links (one per person they evaluate).
  // (Admins who supervise people, e.g. an Admin who is also someone's supervisor, get theirs too.)
  if (scoped && typeof scoped === 'object' && entry.role) {
    const myDown = (raw.down_eval_links || {})[String(entry.name || '').toLowerCase().replace(/\s+/g, ' ').trim()];
    if (myDown && myDown.length) scoped.my_down_evals = markDownDone(raw, entry.name, myDown);
  }
  // Down evaluations this person has SUBMITTED (their own answers, shown back to them).
  if (scoped && typeof scoped === 'object' && entry.role) {
    const mine = downSubmittedBy(raw, entry.name);
    if (mine.length) scoped.my_down_submitted = mine;
  }
  // Down evaluations written ABOUT this person (their supervisor's evaluation of them).
  // The confidential "share only with Professional Staff" question is never included.
  if (scoped && typeof scoped === 'object' && String(entry.role).toLowerCase() !== 'admin') {
    scoped.my_down_received = downReceivedFor(raw, entry.name);
  }
  // Has this person already submitted an up-eval? (matched by evaluator name)
  if (scoped && typeof scoped === 'object' && String(entry.role).toLowerCase() !== 'admin') {
    scoped.my_up_eval_submitted = hasSubmittedUpEval(raw, entry.name);
  }
  return json({
    name: entry.name,
    email: entry.email || '',
    role: entry.role,
    generated_at: raw.generated_at,
    data: scoped,
  });
}

// ── STEP 3: log out ─────────────────────────────
async function handleLogout(request) {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// ── Data scoping (unchanged) ────────────────────
// Association / name normalisation, so a spelling or punctuation difference
// between RA_Roster and Association_Metadata can't hide an association.
const ASSOC_ALIAS = {
  IRC: 'INTERNATIONALRESIDENTIALCOLLEGEIRC',
  INTERNATIONALRESIDENTIALCOLLEGE: 'INTERNATIONALRESIDENTIALCOLLEGEIRC',
  JMW: 'JOHNSONMALONEWEEDON',
};
function akey(a) {
  const k = String(a || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return ASSOC_ALIAS[k] || k;
}
function nkey(n) { return String(n || '').toLowerCase().replace(/\s+/g, ' ').trim(); }
// Associations (names as in assoc_meta) whose metadata field ('sr_name' | 'rlc_name') is this person.
function metaAssocs(raw, field, name) {
  const me = nkey(name);
  return Object.keys(raw.assoc_meta || {}).filter(a => nkey(raw.assoc_meta[a][field]) === me);
}

function buildScopedData(raw, entry) {
  const role = String(entry.role).toLowerCase().replace(/[\s_-]/g, '');
  const name = entry.name;

  if (role === 'admin') return raw;

  if (role === 'ra') {
    // Match by words (ignores comma/order/spacing/case) so "Negley, Allie" == "Allie Negley".
    const tok = n => String(n || '').toLowerCase().replace(/[^a-z\s]/g, ' ').split(/\s+/).filter(Boolean).sort().join(' ');
    const me = tok(name);
    const raKey = Object.keys(raw.ra_data || {}).find(k => k === name) || Object.keys(raw.ra_data || {}).find(k => tok(k) === me);
    return {
      ra_data: raKey ? { [name]: raw.ra_data[raKey] } : {},
      full_roster: (raw.full_roster || []).filter(r => r.name === name || tok(r.name) === me),
      full_labels: raw.full_labels,
    };
  }

  if (role === 'sr') {
    // An SR's associations come from the roster AND from Association_Metadata,
    // so a name-spelling mismatch between the two sheets can't empty their view.
    const srAssocNames = Array.from(new Set([...(raw.sr_assocs?.[name] || []), ...metaAssocs(raw, 'sr_name', name)]));
    const keys = new Set(srAssocNames.map(akey));
    const myRAs = (raw.full_roster || []).filter(r => r.sr_name === name || keys.has(akey(r.association)));
    const raNames = myRAs.map(r => r.name);
    return {
      full_roster: myRAs,
      ra_data: pick(raw.ra_data, raNames),
      sr_assocs: { [name]: srAssocNames },
      assoc_meta: pickByAssoc(raw.assoc_meta, srAssocNames),
      ra_sr_data: pick(raw.ra_sr_data, [name]),
      full_labels: raw.full_labels,
    };
  }

  if (role === 'rlc') {
    const rlcMeta = metaAssocs(raw, 'rlc_name', name);
    const mySRs = Array.from(new Set([
      ...((raw.rlc_srs || {})[name] || []),
      ...rlcMeta.map(a => raw.assoc_meta[a].sr_name).filter(Boolean),
    ]));
    const keys = new Set(rlcMeta.map(akey));
    const myRoster = (raw.full_roster || []).filter(r => mySRs.includes(r.sr_name) || keys.has(akey(r.association)));
    // sr_assocs for this RLC's SRs, plus whatever the metadata says each SR covers
    const srAssocs = pick(raw.sr_assocs, mySRs);
    rlcMeta.forEach(a => {
      const sr = raw.assoc_meta[a].sr_name;
      if (!sr) return;
      srAssocs[sr] = Array.from(new Set([...(srAssocs[sr] || []), a]));
    });
    return {
      full_roster: myRoster,
      ra_data: pick(raw.ra_data, myRoster.map(r => r.name)),
      rlc_srs: { [name]: mySRs },
      sr_assocs: srAssocs,
      assoc_meta: raw.assoc_meta,
      ra_sr_data: pick(raw.ra_sr_data, mySRs),
      sr_rlc_data: pick(raw.sr_rlc_data, [name]),
      full_labels: raw.full_labels,
    };
  }

  if (role === 'pc') {
    const myRLLTs = (raw.ps_rllts || {})[name] || [];
    return {
      ps_rllts: { [name]: myRLLTs },
      rllt_ps_data: pick(raw.rllt_ps_data, [name]),
    };
  }

  if (role === 'rllt') {
    // An RLLT member doesn't get an aggregate view -- just a readback of
    // their own submitted up-eval(s), found by matching their name against
    // the submissions list under whichever Pro-Staff they evaluated.
    const myProStaff = Object.keys(raw.ps_rllts || {}).filter(psName =>
      (raw.ps_rllts[psName] || []).includes(name)
    );
    const mySubmissions = {};
    myProStaff.forEach(psName => {
      const entry = raw.rllt_ps_data && raw.rllt_ps_data[psName];
      if (!entry) return;
      const sub = (entry.submissions || []).find(s => s.name === name);
      if (sub) mySubmissions[psName] = sub;
    });
    return { my_submissions: mySubmissions };
  }

  return {};
}

function normName(n) { return String(n || '').toLowerCase().replace(/\s+/g, ' ').trim(); }
function hasSubmittedUpEval(raw, name) {
  const me = normName(name);
  if (!me) return false;
  return ['ra_sr_data', 'sr_rlc_data', 'rllt_ps_data'].some(function (k) {
    return Object.values(raw[k] || {}).some(function (e) {
      return (e.submissions || []).some(function (s) { return normName(s.name) === me; });
    });
  });
}


// Word-set key so "Last, First" == "First Last" (punctuation / order / case ignored).
function nameTok2(n) { return String(n || '').toLowerCase().replace(/[^a-z\s]/g, ' ').split(/\s+/).filter(Boolean).sort().join(' '); }
// Mark each of this supervisor's down-eval boxes done:true when a submission for that
// evaluatee already exists in the down-eval response data.
function markDownDone(raw, evaluator, list) {
  const me = nameTok2(evaluator);
  const groups = { ra: 'sr_ra', sr: 'rlc_sr', rllt: 'ps_rllt' };
  return list.map(function (e) {
    const g = groups[String(e.role || '').toLowerCase().replace(/[^a-z]/g, '')];
    const data = (raw.down_eval_data || {})[g] || {};
    const k = Object.keys(data).find(function (n) { return nameTok2(n) === me; });
    const subs = k ? (data[k].submissions || []) : [];
    const want = nameTok2(e.evaluatee);
    const done = subs.some(function (s) { return nameTok2(s.evaluatee) === want; });
    return Object.assign({}, e, { done: done });
  });
}


// Everything this person submitted as an evaluator (all of their own answers).
function downSubmittedBy(raw, name) {
  const me = nameTok2(name);
  const out = [];
  Object.keys(raw.down_eval_data || {}).forEach(function (g) {
    const labels = ((raw.down_eval_labels || {})[g] || {}).open || [];
    const byEval = raw.down_eval_data[g] || {};
    Object.keys(byEval).forEach(function (evaluator) {
      if (nameTok2(evaluator) !== me) return;
      (byEval[evaluator].submissions || []).forEach(function (sb) {
        const open = [];
        labels.forEach(function (q, i) {
          const a = sb.open && sb.open['open_' + i];
          if (a) open.push({ q: q, a: a });
        });
        out.push({ group: g, evaluatee: sb.evaluatee, role: sb.role || '', association: sb.association || '', avg: sb.avg, questions: sb.questions || [], open: open });
      });
    });
  });
  return out;
}
// Open-question indexes that must never reach the person being evaluated.
const DOWN_CONFIDENTIAL_OPEN = { sr_ra: [4] };
function downReceivedFor(raw, name) {
  const me = nameTok2(name);
  const out = [];
  const roleOf = { sr_ra: 'SR', rlc_sr: 'RLC', ps_rllt: 'Pro-Staff' };
  Object.keys(raw.down_eval_data || {}).forEach(function (g) {
    const labels = ((raw.down_eval_labels || {})[g] || {}).open || [];
    const hide = DOWN_CONFIDENTIAL_OPEN[g] || [];
    const byEval = raw.down_eval_data[g] || {};
    Object.keys(byEval).forEach(function (evaluator) {
      (byEval[evaluator].submissions || []).forEach(function (sb) {
        if (nameTok2(sb.evaluatee) !== me) return;
        const open = [];
        labels.forEach(function (q, i) {
          const a = sb.open && sb.open['open_' + i];
          if (a && hide.indexOf(i) < 0) open.push({ q: q, a: a });
        });
        out.push({ group: g, from: evaluator, from_role: roleOf[g] || '', avg: sb.avg, questions: sb.questions || [], open: open });
      });
    });
  });
  return out;
}
function pick(obj, keys) {
  const out = {};
  (keys || []).forEach(k => { if (obj && obj[k] !== undefined) out[k] = obj[k]; });
  return out;
}
function pickByAssoc(assocMeta, assocNames) {
  const out = {};
  (assocNames || []).forEach(a => { if (assocMeta && assocMeta[a] !== undefined) out[a] = assocMeta[a]; });
  return out;
}

// ── helpers ─────────────────────────────────────
function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const match = header.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
