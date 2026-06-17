// CorporateHealth — pay-first, then gated dossier upload.
// Flow: pick service -> Stripe Checkout (one-time) -> success redirects to /upload?session_id=...
//       -> server verifies the session is PAID before showing/accepting the dossier upload.
// Money handling is read-only: no card data ever touches this server (Stripe-hosted Checkout).
// PHI: dossiers are stored under ./dossiers/<session_id>/ for dev. PROD MUST move to S3
//      ca-central-1 (Loi 25 data residency) — see STORAGE note below. Keep this box behind HTTPS.

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---- env (reuse the global .env where the Stripe keys live) ----
const ENV = {};
for (const p of ['C:/Users/insta/.claude/.env', path.join(__dirname, '.env')]) {
  try {
    fs.readFileSync(p, 'utf8').split(/\r?\n/).forEach(l => {
      const m = l.match(/^([A-Z0-9_]+)=(.*)$/);
      if (m && ENV[m[1]] === undefined) ENV[m[1]] = m[2].replace(/^["']|["']$/g, '').trim();
    });
  } catch (_) {}
}

// Prefer file-based env locally; fall back to process.env (Render / any host injects vars there).
const SECRET = ENV.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY || '';
const PUBLIC = ENV.STRIPE_PUBLIC_KEY || process.env.STRIPE_PUBLIC_KEY || '';
const WEBHOOK_SECRET = ENV.CORPHEALTH_STRIPE_WEBHOOK_SECRET || ENV.STRIPE_WEBHOOK_SECRET || process.env.CORPHEALTH_STRIPE_WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET || '';
const SITE = ENV.CORPHEALTH_SITE_URL || process.env.CORPHEALTH_SITE_URL || process.env.SITE_URL || 'http://localhost:4100';
const PORT = process.env.PORT || 4100;
const LIVE = SECRET.startsWith('sk_live');
let stripe = null;
if (SECRET) { try { stripe = require('stripe')(SECRET); } catch (e) { console.log('stripe init failed', e.message); } }

const DOSSIERS = path.join(__dirname, 'dossiers');
fs.mkdirSync(DOSSIERS, { recursive: true });

// ---- catalog: SKU -> { label, amount(cents, CAD), mode } ----
// One-time per-case services use pay-then-upload. Annual bundles are also one-time charges here;
// Enterprise is quote-only (no online price). Amounts mirror the approved catalog.
const CATALOG = {
  // à-la-carte per-case (the natural pay-then-upload services)
  'file-review':   { label: 'Disability / Absence File Review', amount: 45000 },
  'fitness':       { label: 'Fitness-for-Duty Evaluation',      amount: 35000 },
  'pre-employment':{ label: 'Pre-employment / Pre-placement Medical', amount: 20000 },
  'surveillance':  { label: 'Periodic / Surveillance Exam (per worker / cycle)', amount: 15000 },
  'rtw':           { label: 'Return-to-Work & Accommodation Plan', amount: 30000 },
  'ime':           { label: 'Independent Medical Examination (IME)', amount: 150000 },
  'mro':           { label: 'Drug & Alcohol — MRO Review (per result)', amount: 5000 },
  'exec':          { label: 'Executive / Preventive Health Assessment', amount: 195000 },
  'hra':           { label: 'Workforce HRA (per employee)', amount: 6000 },
  'bilan':         { label: 'Bilan de santé annuel — dépistages Santé Canada (per employee/year)', amount: 5000 },
  'vaccination':   { label: 'Workplace / Travel Vaccination (per employee)', amount: 3900 },
  // annual programs
  'starter':       { label: 'Starter — Occupational Essentials (annual, up to 10)', amount: 350000 },
  'growth':        { label: 'Growth — Workforce Health (annual, up to 50)', amount: 1250000 },
  // 'enterprise' intentionally absent: quote-only -> contact form
};

// Workforce SKUs deliver via an employee ROSTER (we invite each employee to Spruce and run the
// service there). Case/risk SKUs deliver via a DOSSIER upload. The post-payment page branches on this.
const ROSTER_SKUS = new Set(['bilan', 'hra', 'exec', 'vaccination', 'starter', 'growth']);

const app = express();

// ---- Stripe webhook FIRST (needs raw body, before express.json) ----
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe) return res.json({ ok: true, note: 'stripe disabled' });
  let event;
  try {
    event = WEBHOOK_SECRET
      ? stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], WEBHOOK_SECRET)
      : JSON.parse(req.body);
  } catch (e) { return res.status(400).send('bad signature: ' + e.message); }
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    // mark the session paid in our local ledger so /upload can gate on it even if Stripe is slow
    try {
      const dir = path.join(DOSSIERS, sanitizeId(s.id));
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'paid.json'), JSON.stringify({
        sessionId: s.id, sku: (s.metadata || {}).sku || null, amount: s.amount_total,
        currency: s.currency, email: (s.customer_details || {}).email || null,
        paidAt: new Date().toISOString()
      }, null, 2));
    } catch (_) {}
  }
  res.json({ received: true });
});

app.use(express.json());

// ---- helpers ----
function sanitizeId(id) { return String(id || '').replace(/[^a-zA-Z0-9_]/g, '').slice(0, 80); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// Verify a checkout session is genuinely paid (live Stripe is the source of truth; local ledger is a fallback).
async function sessionPaid(sessionId) {
  const id = sanitizeId(sessionId);
  if (!id) return null;
  if (stripe) {
    try {
      const s = await stripe.checkout.sessions.retrieve(id);
      if (s && s.payment_status === 'paid') return { id, sku: (s.metadata || {}).sku || null, email: (s.customer_details || {}).email || null, amount: s.amount_total };
      return null;
    } catch (_) { /* fall through to ledger */ }
  }
  // fallback: webhook-written ledger
  try { const p = JSON.parse(fs.readFileSync(path.join(DOSSIERS, id, 'paid.json'), 'utf8')); return { id, sku: p.sku, email: p.email, amount: p.amount }; } catch (_) { return null; }
}

// ---- create a Checkout Session ----
app.post('/api/checkout', async (req, res) => {
  const sku = String((req.body || {}).sku || '');
  const qty = Math.max(1, Math.min(2000, parseInt((req.body || {}).quantity, 10) || 1));
  const item = CATALOG[sku];
  if (!item) return res.status(400).json({ ok: false, error: 'unknown or quote-only service; use the contact form' });
  if (!stripe) return res.status(503).json({ ok: false, error: 'billing not configured' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: { currency: 'cad', product_data: { name: 'CorporateHealth — ' + item.label }, unit_amount: item.amount },
        quantity: qty
      }],
      metadata: { sku, quantity: String(qty) },
      success_url: SITE + '/upload?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: SITE + '/?canceled=1#pricing',
    });
    res.json({ ok: true, url: session.url });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---- gated dossier upload PAGE (only renders if the session is paid) ----
app.get('/upload', async (req, res) => {
  const paid = await sessionPaid(req.query.session_id);
  if (!paid) {
    return res.status(402).send(uploadShell(`<div class="gate">
      <h1>Payment required</h1>
      <p>This upload page unlocks only after a completed payment. If you just paid and see this, wait a few seconds and refresh — or <a href="/#pricing">return to pricing</a>.</p>
    </div>`));
  }
  const sku = paid.sku || '';
  const label = (CATALOG[sku] || {}).label || 'your service';
  const isRoster = ROSTER_SKUS.has(sku);
  const heading = isRoster ? 'Send us your employee roster' : 'Send us the case dossier';
  const sub = isRoster
    ? `For <b>${esc(label)}</b>. List the employees who opted in (name + email or mobile). We invite each one to Spruce — your private, secure messaging channel — and run the service there. You never receive an employee's diagnosis or record, only completion and de-identified aggregate insight.`
    : `For <b>${esc(label)}</b>. Upload the medical records, forms, or case file — any size, PDF or images. Handled under signed agreement, encrypted; you receive only the minimized report (fitness / limitations), never the diagnosis.`;
  const fields = isRoster
    ? `<label>Employee roster — one per line: <span style="font-weight:400;color:#64748B">Name, email or mobile</span>
         <textarea name="roster" rows="6" placeholder="Marie Tremblay, marie@acme.ca&#10;Jean Côté, 514-555-0142" required></textarea></label>
       <label class="file">Or upload a roster file (CSV / XLSX — optional)<input type="file" name="files" multiple></label>`
    : `<label>Notes / the specific question to answer<textarea name="notes" rows="3"></textarea></label>
       <label class="file">Dossier files<input type="file" name="files" multiple required></label>`;
  res.send(uploadShell(`<div class="card">
    <span class="ok">✓ Payment received</span>
    <h1>${heading}</h1>
    <p class="sub">${sub}</p>
    <form id="f" method="post" action="/api/upload" enctype="multipart/form-data">
      <input type="hidden" name="session_id" value="${esc(paid.id)}">
      <label>Your name<input name="contact_name" required></label>
      <label>Company<input name="company" required></label>
      <label>Email for confirmation<input type="email" name="email" value="${esc(paid.email || '')}" required></label>
      ${fields}
      <button type="submit">${isRoster ? 'Submit roster securely' : 'Upload securely'}</button>
      <p id="msg"></p>
    </form>
  </div>`) + uploadScript());
});

// ---- accept the upload (re-verify paid; store under the session id) ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const id = sanitizeId((req.body || {}).session_id);
    const dir = path.join(DOSSIERS, id || ('orphan_' + crypto.randomBytes(4).toString('hex')));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safe = (file.originalname || 'file').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
    cb(null, Date.now() + '_' + safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024, files: 40 } });

app.post('/api/upload', upload.array('files', 40), async (req, res) => {
  const paid = await sessionPaid((req.body || {}).session_id);
  if (!paid) return res.status(402).json({ ok: false, error: 'payment not verified — upload rejected' });
  const id = sanitizeId(req.body.session_id);
  const files = (req.files || []).map(f => ({ name: f.originalname, stored: path.basename(f.path), size: f.size }));
  try {
    fs.writeFileSync(path.join(DOSSIERS, id, 'intake.json'), JSON.stringify({
      sessionId: id, sku: paid.sku, mode: ROSTER_SKUS.has(paid.sku) ? 'roster' : 'dossier',
      contact_name: req.body.contact_name, company: req.body.company,
      email: req.body.email, notes: req.body.notes || null, roster: req.body.roster || null,
      files, uploadedAt: new Date().toISOString()
    }, null, 2));
  } catch (_) {}
  res.json({ ok: true, received: files.length, files: files.map(f => f.name) });
});

// ---- static site LAST (so /upload and /api/* win) ----
app.use(express.static(__dirname, { extensions: ['html'] }));

function uploadShell(inner) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload dossier · CorporateHealth</title>
<link href="https://fonts.googleapis.com/css2?family=EB+Garamond:wght@600;700&family=Lato:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{--navy:#1E3A8A;--gold:#B45309;--ink:#0F172A;--muted:#64748B;--bg:#F8FAFC;--border:#CBD5E1;--green:#059669}
*{box-sizing:border-box;margin:0}body{font-family:Lato,system-ui,sans-serif;background:var(--bg);color:var(--ink);line-height:1.6;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:2rem}
.card,.gate{background:#fff;border:1px solid var(--border);border-radius:16px;padding:2.5rem;max-width:560px;width:100%;box-shadow:0 12px 24px -8px rgba(15,23,42,.12)}
h1{font-family:'EB Garamond',serif;color:var(--navy);font-size:2rem;margin:.4rem 0 .6rem}
.sub{color:var(--muted);margin-bottom:1.5rem}.ok{color:var(--green);font-weight:900;font-size:.85rem;letter-spacing:.04em}
label{display:block;font-weight:700;font-size:.9rem;margin:1rem 0 .3rem}
input,textarea{width:100%;padding:.7rem;border:1px solid var(--border);border-radius:8px;font:inherit}
input[type=file]{padding:.5rem;background:var(--bg)}
button{margin-top:1.5rem;width:100%;background:var(--navy);color:#fff;border:0;border-radius:9px;padding:.9rem;font-weight:700;font-size:1rem;cursor:pointer}
button:hover{background:#1E40AF}button:disabled{opacity:.6}
#msg{margin-top:1rem;font-weight:700}a{color:var(--navy)}
.gate h1{color:var(--gold)}
</style></head><body>${inner}</body></html>`;
}
function uploadScript() {
  return `<script>
const f=document.getElementById('f');
if(f)f.addEventListener('submit',async e=>{e.preventDefault();const b=f.querySelector('button'),m=document.getElementById('msg');const orig=b.textContent;
b.disabled=true;b.textContent='Sending…';m.textContent='';
try{const r=await fetch('/api/upload',{method:'POST',body:new FormData(f)});const j=await r.json();
if(j.ok){m.style.color='#059669';m.textContent='✓ Received — thank you. We will reach out via Spruce and email to begin.';f.querySelectorAll('input,textarea,button').forEach(x=>x.disabled=true);}
else{m.style.color='#DC2626';m.textContent='✕ '+(j.error||'submission failed');b.disabled=false;b.textContent=orig;}}
catch(err){m.style.color='#DC2626';m.textContent='✕ '+err.message;b.disabled=false;b.textContent=orig;}});
</script>`;
}

app.listen(PORT, () => {
  console.log(`CorporateHealth on ${SITE} (port ${PORT})`);
  console.log(`  billing: ${stripe ? (LIVE ? 'Stripe LIVE ⚠' : 'Stripe TEST') : 'DISABLED (no key)'} | webhook: ${WEBHOOK_SECRET ? 'verified' : 'UNVERIFIED (set CORPHEALTH_STRIPE_WEBHOOK_SECRET)'}`);
  console.log(`  dossiers -> ${DOSSIERS}  (DEV ONLY — move to S3 ca-central-1 for Loi 25 before go-live)`);
});

module.exports = { app, sessionPaid, CATALOG };
