// generate_infographics.mjs — the README illustration set, Apple HIG edition.
// Run:  deno run --allow-read --allow-write assets/generate_infographics.mjs
// Emits 12 SVGs into Assets/infographics/ (same filenames the README links).
//
// Design system (Human Interface Guidelines):
//   white canvas · #1D1D1F ink · #6E6E73 secondary · #D2D2D7 hairlines ·
//   #F5F5F7 fills · one accent (#0071E3) · 8-pt grid · 18/12 px radii ·
//   SF-style type stack · clarity and deference: content first, chrome hairline.
// Pure ASCII in code; copy strings carry typographic punctuation on purpose.

const W = 1120;
const INK = '#1D1D1F', SUB = '#6E6E73', HAIR = '#D2D2D7', FILL = '#F5F5F7',
      BLUE = '#0071E3', BLUE_T = '#EAF3FF', GREEN = '#34C759', AMBER = '#FF9F0A',
      WHITE = '#FFFFFF';
const FONT = "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable Text', 'Segoe UI', Helvetica, Arial, sans-serif";

const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function T(x, y, s, o = {}) {
  const { size = 15, weight = 400, fill = INK, anchor = 'start', ls } = o;
  const extra = ls ? ` letter-spacing="${ls}"` : '';
  return `<text x="${x}" y="${y}" font-size="${size}" font-weight="${weight}"` +
         ` fill="${fill}" text-anchor="${anchor}"${extra}>${esc(s)}</text>`;
}

function svgDoc(h, body, label) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${h}" viewBox="0 0 ${W} ${h}" role="img" aria-label="${esc(label)}">\n` +
         `<rect width="${W}" height="${h}" fill="${WHITE}"/>\n<g font-family="${FONT}">\n${body}\n</g>\n</svg>\n`;
}

const card = (x, y, w, h, fill = WHITE, stroke = HAIR, r = 18) =>
  `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}" stroke="${stroke}" stroke-width="1"/>`;

const rule = (x, y, w, color = HAIR) =>
  `<line x1="${x}" y1="${y}" x2="${x + w}" y2="${y}" stroke="${color}" stroke-width="1"/>`;

function chip(x, y, w, h, title, body, { glyph = null, tone = BLUE, maxChars = 44 } = {}) {
  let g = card(x, y, w, h, FILL, 'none', 14);
  const tx = x + (glyph ? 52 : 18);
  if (glyph) g += glyphPath(x + 24, y + h / 2 - (body ? 8 : 0), glyph, tone);
  g += T(tx, y + (body ? 26 : h / 2 + 5), title, { size: 14, weight: 600, fill: INK });
  if (body) {
    wrap(body, maxChars).slice(0, 3).forEach((ln, j) => {
      g += T(tx, y + 48 + j * 17, ln, { size: 12.5, fill: SUB });
    });
  }
  return g;
}

function glyphPath(cx, cy, kind, color = BLUE) {
  const s = `fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"`;
  switch (kind) {
    case 'eye': return `<g ${s}><path d="M ${cx - 13} ${cy} q 13 -12 26 0 q -13 12 -26 0"/><circle cx="${cx}" cy="${cy}" r="3.4"/></g>`;
    case 'shield': return `<g ${s}><path d="M ${cx} ${cy - 13} l 10 4.5 v 6.5 q 0 7.5 -10 11 q -10 -3.5 -10 -11 v -6.5 z"/></g>`;
    case 'check': return `<g ${s}><path d="M ${cx - 9} ${cy + 1} l 6 6.5 l 12.5 -14"/></g>`;
    case 'arrow': return `<g ${s}><path d="M ${cx - 10} ${cy} h 18 M ${cx + 2} ${cy - 6.5} l 6.5 6.5 l -6.5 6.5"/></g>`;
    case 'door': return `<g ${s}><rect x="${cx - 8}" y="${cy - 12}" width="16" height="24" rx="2"/><circle cx="${cx + 3.5}" cy="${cy + 2}" r="1.6"/></g>`;
    case 'bubble': return `<g ${s}><path d="M ${cx - 11} ${cy - 8} h 22 a 3 3 0 0 1 3 3 v 8 a 3 3 0 0 1 -3 3 h -14 l -6 5 v -5 h -2 a 3 3 0 0 1 -3 -3 v -8 a 3 3 0 0 1 3 -3"/></g>`;
    case 'clock': return `<g ${s}><circle cx="${cx}" cy="${cy}" r="10.5"/><path d="M ${cx} ${cy - 5} v 5 l 4 3"/></g>`;
    case 'lens': return `<g ${s}><circle cx="${cx - 2}" cy="${cy - 2}" r="7.5"/><path d="M ${cx + 3.5} ${cy + 3.5} l 7 7"/></g>`;
    case 'server': return `<g ${s}><rect x="${cx - 11}" y="${cy - 9}" width="22" height="7.5" rx="2"/><rect x="${cx - 11}" y="${cy + 1.5}" width="22" height="7.5" rx="2"/><circle cx="${cx - 6}" cy="${cy - 5.2}" r="1.2"/><circle cx="${cx - 6}" cy="${cy + 5.2}" r="1.2"/></g>`;
    case 'radar': return `<g ${s}><circle cx="${cx}" cy="${cy}" r="10.5"/><circle cx="${cx}" cy="${cy}" r="4.5"/><path d="M ${cx} ${cy} l 8 -7.5"/></g>`;
    case 'doc': return `<g ${s}><rect x="${cx - 8}" y="${cy - 11}" width="16" height="22" rx="2"/><path d="M ${cx - 3.5} ${cy - 4} h 7 M ${cx - 3.5} ${cy} h 7 M ${cx - 3.5} ${cy + 4} h 4.5"/></g>`;
    case 'undo': return `<g ${s}><path d="M ${cx - 9} ${cy - 3} a 9 8 0 1 1 2 8.5"/><path d="M ${cx - 10} ${cy - 9} l 0.5 6.5 l 6.5 -1"/></g>`;
    default: return '';
  }
}

function eyebrow(x, y, s) {
  return T(x, y, s.toUpperCase(), { size: 11, weight: 600, fill: BLUE, ls: '1.4' });
}

// ── 12 infographics ─────────────────────────────────────────────────────────

function hero() {
  const W2 = 340, gap = 20, x0 = 64, y0 = 214, h = 118;
  let b = eyebrow(64, 84, 'Free · Open source · Windows 10 & 11');
  b += T(64, 138, 'AutoCommand', { size: 46, weight: 700 });
  b += T(64, 174, 'See what your Windows PC is really doing — and stop what you don\u2019t want.',
         { size: 19, fill: SUB });
  const chips = [
    ['eye',   'Watch',   'every program that talks to the internet, in plain English'],
    ['shield','Contain', 'stop anything you don\u2019t want — one click, undo included'],
    ['check', 'Prove',   'the evidence in readable local files, not a black box'],
  ];
  chips.forEach(([g, t, d], i) => {
    const x = x0 + i * (W2 + gap);
    b += card(x, y0, W2, h);
    b += glyphPath(x + 30, y0 + 34, g);
    b += T(x + 56, y0 + 39, t, { size: 17, weight: 600 });
    wrap(d, 40).slice(0, 2).forEach((ln, j) => {
      b += T(x + 24, y0 + 70 + j * 18, ln, { size: 13, fill: SUB });
    });
  });
  b += T(64, y0 + h + 34, 'Complements your antivirus — they do different jobs. No installer. It reports nothing about you to anyone.',
         { size: 13, fill: SUB });
  return svgDoc(392, b, 'AutoCommand — see what your Windows PC is really doing, and stop what you don\u2019t want');
}

function fiveMinutes() {
  let b = eyebrow(64, 56, 'Try it in five minutes');
  const steps = [
    ['1', 'Download & unzip', 'AutoCommand-v\u2026-win-x64.zip from Releases \u2014 checksums included, no installer.'],
    ['2', 'Run as administrator', 'Same reason Task Manager asks: to see the whole machine, not just your user.'],
    ['3', 'Look around, ask something', 'The first screen lists every program talking to the internet right now.'],
  ];
  const cw = 317, gap = 24, x0 = 64, y0 = 78, ch = 118;
  steps.forEach(([n, t, d], i) => {
    const x = x0 + i * (cw + gap);
    b += card(x, y0, cw, ch);
    b += T(x + 20, y0 + 40, n, { size: 26, weight: 700, fill: BLUE });
    b += T(x + 52, y0 + 37, t, { size: 14.5, weight: 600 });
    wrap(d, 42).slice(0, 2).forEach((ln, j) => {
      b += T(x + 20, y0 + 64 + j * 17, ln, { size: 12.5, fill: SUB });
    });
  });
  b += T(64, y0 + ch + 30, 'Air-gapped PC? Everything works offline \u2014 bring your own Sysmon64.exe (download it on any connected machine, move it over by USB).',
         { size: 13, fill: SUB });
  return svgDoc(286, b, 'Three steps: download and unzip, run as administrator, look around');
}

function rowAnatomy() {
  let b = eyebrow(64, 56, 'How to read one row');
  // the row itself
  const rx = 64, ry = 76, rw = 992, rh = 64;
  b += card(rx, ry, rw, rh, FILL, 'none', 12);
  b += glyphPath(rx + 34, ry + 32, 'lens');
  b += T(rx + 66, ry + 27, 'svchost.exe  \u2192  Google LLC  (schtask \u2192 Chrome updater)', { size: 14.5, weight: 600 });
  b += T(rx + 66, ry + 48, '443/tcp \u00B7 sent 12,401 \u00B7 received 198,532 \u00B7 first seen 09:41 \u00B7 parent: scheduled task', { size: 12.5, fill: SUB });
  b += `<rect x="${rx + rw - 96}" y="${ry + 17}" width="72" height="30" rx="15" fill="${BLUE}"/>`;
  b += T(rx + rw - 60, ry + 36, 'Block', { size: 13, weight: 600, fill: WHITE, anchor: 'middle' });
  // anatomy callouts
  const items = [
    ['Who, and who started it', 'the process, its parent, and the scheduled task that launched it'],
    ['To whom, how much, how long', 'resolved organization, packet counts both ways, first-seen time'],
    ['Right-click asks more', 'spawn chain, live sockets, real process name (Sysmon), WSL diagnosis'],
    ['TX-only lens (off by default)', 'sent packets and never heard one word back \u2014 the shape of a beacon'],
  ];
  const cw = 484, ch = 74, gy = 168;
  items.forEach(([t, d], i) => {
    const x = 64 + (i % 2) * (cw + 24), y = gy + Math.floor(i / 2) * (ch + 18);
    b += card(x, y, cw, ch);
    b += T(x + 20, y + 30, t, { size: 14, weight: 600 });
    b += T(x + 20, y + 52, d, { size: 12.5, fill: SUB });
  });
  return svgDoc(336, b, 'Anatomy of one connection row: who, to whom, how much, how long \u2014 plus the right-click menu and the TX-only lens');
}

function appMap() {
  let b = eyebrow(64, 56, 'Where everything lives');
  b += T(64, 88, 'Grouped by the question you\u2019re asking \u2014 not by what the tools do internally.', { size: 15, fill: SUB });
  const groups = [
    ['WATCH', 'a question about traffic', [
      ['Process Monitor', 'every connection, who launched it'],
      ['Exfil', 'typing vs telemetry, hourly, opt-in'],
      ['Matrix rain', 'the same feed, replayed live'],
    ]],
    ['CONTAIN', 'a decision about traffic', [
      ['Firewall', 'block, gate, whitelist, profile'],
      ['Blocks', 'everything stopped, one list'],
      ['Audit', 'everything the app did, one ledger'],
    ]],
    ['SYSTEM', 'everything else', [
      ['Be My Guest', 'invite your AI assistant, locally'],
      ['Settings', 'preferences and instrumentation'],
      ['Investigate', 'one process, one verdict (Advanced)'],
    ]],
  ];
  const cw = 328, gap = 20, x0 = 64, y0 = 112, gh = 328;
  groups.forEach(([name, tag, rows], i) => {
    const x = x0 + i * (cw + gap);
    b += card(x, y0, cw, gh);
    b += T(x + 22, y0 + 34, name, { size: 13, weight: 700, fill: BLUE, ls: '1.2' });
    b += T(x + 22, y0 + 56, tag, { size: 12.5, fill: SUB });
    b += rule(x + 22, y0 + 70, cw - 44);
    rows.forEach(([t, d], j) => {
      const y = y0 + 88 + j * 78;
      b += T(x + 22, y + 6, t, { size: 14, weight: 600 });
      b += T(x + 22, y + 26, d, { size: 12, fill: SUB });
      if (j < 2) b += rule(x + 22, y + 46, cw - 44);
    });
  });
  return svgDoc(468, b, 'The sidebar, grouped by the question you\u2019re asking: Watch, Contain, System');
}

function watchTools() {
  let b = eyebrow(64, 56, 'Watch: the questions a list can\u2019t answer');
  const cards = [
    ['lens', 'Site Doctor', '\u201CWhy is this site slow?\u201D', '~30-second check: DNS rotation sampling, per-edge TCP and TLS hello shapes, a control host for comparison \u2014 plus the question nothing else asks: were this page\u2019s other hosts silently blocked?'],
    ['server', 'WSL doctor', '\u201CWhy is WSL offline?\u201D', 'A staged, read-only pipeline from host egress down to the Hyper-V firewall layer, ending in one plain verdict. It never starts the utility VM.'],
    ['radar', 'Spawn Watches', '\u201CWhat did svchost spawn?\u201D', 'Name-based prefilters evaluated the moment a process is born \u2014 caught at birth, never chased after the fact. Drop a JSON rule in; hits archive daily.'],
  ];
  const cw = 328, gap = 20, x0 = 64, y0 = 78, ch = 190;
  cards.forEach(([g, t, q, d], i) => {
    const x = x0 + i * (cw + gap);
    b += card(x, y0, cw, ch);
    b += glyphPath(x + 32, y0 + 36, g);
    b += T(x + 58, y0 + 41, t, { size: 15.5, weight: 600 });
    b += T(x + 22, y0 + 72, q, { size: 13, weight: 600, fill: BLUE });
    // wrapped body: three lines max, hand-broken
    const lines = wrap(d, 46);
    lines.forEach((ln, j) => { b += T(x + 22, y0 + 98 + j * 19, ln, { size: 12, fill: SUB }); });
  });
  return svgDoc(308, b, 'Site Doctor, WSL diagnosis, Spawn Watches \u2014 read-only answers to deeper questions');
}

function plainEnglish() {
  let b = eyebrow(64, 56, 'When something looks odd');
  b += T(64, 90, 'The 2 a.m. worry, from this app\u2019s own development machine:', { size: 15, fill: SUB });
  // worry bubble
  b += card(64, 112, 460, 64, FILL, 'none', 14);
  b += T(84, 138, '\u201Csvchost.exe is uploading packets\u201D', { size: 14.5, weight: 600 });
  b += T(84, 160, 'sounds alarming at midnight \u2014 reinstall? forums?', { size: 12.5, fill: SUB });
  b += glyphPath(548, 144, 'arrow');
  // the row that answers it
  b += card(580, 112, 476, 64, WHITE, HAIR, 14);
  b += T(600, 138, 'Chrome\u2019s updater, downloading from Google\u2019s', { size: 13.5, weight: 600 });
  b += T(600, 160, 'own servers \u2014 launched by a scheduled task. One row proved it.', { size: 12.5, fill: SUB });
  b += T(64, 218, 'No panic, no reinstall, no forum archaeology. When a row surprises you, that\u2019s the moment to click \u2014 most rows, you\u2019ll never need to think about.',
         { size: 13.5, fill: SUB });
  return svgDoc(252, b, 'The 2 a.m. svchost worry, answered by one row');
}

function contain() {
  let b = eyebrow(64, 56, 'Contain: stopping is safe');
  const chips = [
    ['doc',    'Pre-block brief', 'says exactly what the rule will do before you confirm'],
    ['undo',   'One-click undo',  'every block reverses in one click, with the reason you gave'],
    ['clock',  'Gates',           'open one blocked target for 1 / 10 / 30 / 60 min, then re-arm'],
    ['check',  'Containment proof', 'attempts joined against live sockets: contained \u00B7 stale flow \u00B7 leak'],
  ];
  const cw = 484, ch = 78, gy = 78;
  chips.forEach(([g, t, d], i) => {
    const x = 64 + (i % 2) * (cw + 24), y = gy + Math.floor(i / 2) * (ch + 18);
    b += chip(x, y, cw, ch, t, d, { glyph: g, maxChars: 54 });
  });
  // panic + lockdown strip
  b += card(64, gy + 2 * (ch + 18) + 6, 992, 66, BLUE_T, 'none', 14);
  b += T(86, gy + 2 * (ch + 18) + 41, 'If it all goes wrong:', { size: 14, weight: 600 });
  b += T(228, gy + 2 * (ch + 18) + 41, 'the \uD83DDEA1 Restore Internet button undoes every block the app ever made.', { size: 13.5, fill: INK });
  b += T(86, gy + 2 * (ch + 18) + 62, 'Even lockdown photographs every firewall rule first \u2014 Restore snapshot brings them back.',
         { size: 12.5, fill: SUB });
  return svgDoc(356, b, 'Pre-block brief, reversible blocks, self-closing gates, containment proof, panic button, lockdown snapshots');
}

function shieldsUp() {
  let b = eyebrow(64, 56, 'Shields Up \u2014 the doors Windows leaves open');
  const doors = [
    ['SSTP VPN service', 'and its miniports'],
    ['Wi-Fi Direct', 'the ghost hotspot'],
    ['Kernel debug', 'KDNET adapter off'],
    ['VPN services', 'RasMan \u00B7 IKEEXT \u00B7 \u2026'],
    ['LLMNR \u00B7 NetBIOS', 'the poisoning class'],
    ['mDNS', 'scoped block, honest'],
  ];
  const dw = 152, dh = 74, gap = 14, x0 = 64, y0 = 78;
  doors.forEach(([t, d], i) => {
    const x = x0 + (i % 4) * (dw + gap), y = y0 + Math.floor(i / 4) * (dh + 14);
    b += card(x, y, dw, dh);
    // toggle pill on top-right, text below it — never side by side (the
    // titles run too wide and would collide with the pill)
    b += `<rect x="${x + dw - 40}" y="${y + 10}" width="28" height="16" rx="8" fill="${GREEN}"/>`;
    b += `<circle cx="${x + dw - 12}" cy="${y + 18}" r="5.5" fill="${WHITE}"/>`;
    b += T(x + 14, y + 44, t, { size: 12.5, weight: 600 });
    b += T(x + 14, y + 62, d, { size: 11, fill: SUB });
  });
  // right column: hardening + audit
  b += card(x0 + 4 * (dw + gap), y0, 992 + 64 - x0 - 4 * (dw + gap), 2 * dh + 14, BLUE_T, 'none', 18);
  b += T(x0 + 4 * (dw + gap) + 20, y0 + 30, 'Also on the board', { size: 13.5, weight: 600 });
  ['IPv6 \u00B7 LSA PPL \u00B7 UAC strictness', 'hosts-file audit', 'vendor telemetry opt-outs',
   'startup & tasks', 'firewall profiles', 'leftover-account audit (new)']
    .forEach((s, j) => { b += T(x0 + 4 * (dw + gap) + 20, y0 + 56 + j * 22, '\u2713  ' + s, { size: 12, fill: INK }); });
  b += T(64, y0 + 2 * dh + 14 + 34,
    'A standalone native WinUI 3 app \u2014 born here as a tab; its engine (ShieldsUp.Core) is this repository\u2019s and still powers AutoCommand. Closing a door is one click; re-opening it is a decision only you make.',
    { size: 13, fill: SUB });
  return svgDoc(300, b, 'The doors Windows leaves open: SSTP, Wi-Fi Direct, kernel debug, VPN services; LLMNR, NetBIOS, mDNS; hardening, hosts file, vendor opt-outs, startup and tasks, firewall profiles, leftover accounts');
}

function beMyGuest() {
  let b = eyebrow(64, 56, 'Be My Guest \u2014 your AI assistant, invited');
  const boxes = [
    ['You', 'press Start'],
    ['Local bridge', 'loopback \u00B7 bearer token'],
    ['AgentProxy', 'small, unprivileged'],
    ['Your assistant', 'MCP client'],
  ];
  const bw = 214, bh = 74, gap = 32, x0 = 64, y0 = 80;
  boxes.forEach(([t, d], i) => {
    const x = x0 + i * (bw + gap);
    b += card(x, y0, bw, bh);
    b += T(x + 20, y0 + 30, t, { size: 14.5, weight: 600 });
    b += T(x + 20, y0 + 52, d, { size: 12, fill: SUB });
    if (i < 3) b += glyphPath(x + bw + gap / 2, y0 + bh / 2, 'arrow');
  });
  b += T(64, y0 + bh + 34, 'The door is only open while you keep it open: sessions start only from the Start button, and every tool call lands in the live activity log.',
         { size: 13.5, fill: SUB });
  b += T(64, y0 + bh + 58, 'No cloud middleman, no account. One honest boundary: while a session runs, its token lives in a local file \u2014 anything running as your user can read what the AI reads.',
         { size: 13.5, fill: SUB });
  return svgDoc(240, b, 'You press Start, a local bridge session runs on your machine, your MCP assistant connects through the unprivileged AgentProxy');
}

function privacy() {
  let b = eyebrow(64, 56, 'What it sends about you');
  b += card(64, 78, 992, 64, BLUE_T, 'none', 16);
  b += T(86, 116, 'Nothing, by default. Everything happens on your computer.', { size: 16.5, weight: 600 });
  const items = [
    ['RDAP lookups', 'automatic, HTTPS \u2014 asks the registry who owns an IP; sends the queried IP and nothing else'],
    ['Sysmon download', 'only when you click Install \u2014 Authenticode-verified before it runs'],
    ['DBX blob', 'secure-boot revocation list \u2014 only from Shields Up, only that file'],
  ];
  const cw = 328, gap = 20, x0 = 64, y0 = 162, ch = 92;
  items.forEach(([t, d], i) => {
    const x = x0 + i * (cw + gap);
    b += card(x, y0, cw, ch);
    b += T(x + 20, y0 + 30, t, { size: 14, weight: 600 });
    const lines = wrap(d, 44);
    lines.slice(0, 3).forEach((ln, j) => { b += T(x + 20, y0 + 52 + j * 17, ln, { size: 11.5, fill: SUB }); });
  });
  b += T(64, y0 + ch + 32, 'The one optional extra \u2014 an anonymous daily count with no identifiers, not even a random one \u2014 is off unless you say yes.',
         { size: 13.5, fill: SUB });
  return svgDoc(330, b, 'Nothing by default: three narrow lookups spelled out, everything else local');
}

function safety() {
  let b = eyebrow(64, 56, 'Built so you can experiment safely');
  const chips = [
    ['doc',  'Readable, local, first', 'every record lands in plain files on your machine \u2014 no formats you can\u2019t open'],
    ['undo', 'Undo everything', 'per block, per gate, or all at once with the panic button'],
    ['check','Leaving is honest', 'delete the folder and the app\u2019s files go with it \u2014 what outlives it is listed, not hidden'],
  ];
  const cw = 328, gap = 20, x0 = 64, y0 = 78, ch = 118;
  chips.forEach(([g, t, d], i) => {
    const x = x0 + i * (cw + gap);
    b += card(x, y0, cw, ch);
    b += glyphPath(x + 30, y0 + 34, g);
    b += T(x + 56, y0 + 39, t, { size: 14.5, weight: 600 });
    const lines = wrap(d, 40);
    lines.slice(0, 3).forEach((ln, j) => { b += T(x + 22, y0 + 70 + j * 18, ln, { size: 12, fill: SUB }); });
  });
  b += T(64, y0 + ch + 32, 'TECHNICAL_NOTES.md lists every location the app writes \u2014 nothing is a mystery.',
         { size: 13, fill: SUB });
  return svgDoc(278, b, 'Local-first, undo everything, honest about what outlives the folder');
}

function lineage() {
  let b = eyebrow(64, 56, 'Where it came from');
  const stops = [
    ['SystemMonitor', 'firmware, UEFI/DBX and Defender forensics dashboard'],
    ['AutoCommand II', 'the core engines rebuilt in F#'],
    ['AutoCommand III', 'the engine stack, hardened and split from the shell'],
    ['AutoCommand', 'one repository, the whole family tree'],
  ];
  const bw = 214, bh = 84, gap = 32, x0 = 64, y0 = 78;
  stops.forEach(([t, d], i) => {
    const x = x0 + i * (bw + gap);
    b += card(x, y0, bw, bh, i === 3 ? BLUE_T : FILL, 'none', 14);
    b += T(x + 20, y0 + 32, t, { size: 14.5, weight: 600 });
    const lines = wrap(d, 30);
    lines.slice(0, 2).forEach((ln, j) => { b += T(x + 20, y0 + 54 + j * 17, ln, { size: 11.5, fill: SUB }); });
    if (i < 3) b += glyphPath(x + bw + gap / 2, y0 + bh / 2, 'arrow');
  });
  b += T(64, y0 + bh + 32, 'The precursor\u2019s complete source tree and commit history live under systemmonitor/ ; its classic v3.x releases remain on the old Releases page.',
         { size: 13, fill: SUB });
  return svgDoc(230, b, 'SystemMonitor, the precursor, to AutoCommand II and III, to AutoCommand today');
}

// naive width-aware wrapper: ~0.52 * size per char for Segoe UI at these sizes
function wrap(s, maxChars) {
  const words = s.split(' ');
  const lines = [];
  let cur = '';
  for (const w of words) {
    if ((cur + ' ' + w).trim().length <= maxChars) cur = (cur + ' ' + w).trim();
    else { if (cur) lines.push(cur); cur = w; }
  }
  if (cur) lines.push(cur);
  return lines;
}

// ── emit ────────────────────────────────────────────────────────────────────
const files = {
  'hero': hero(), 'five-minutes': fiveMinutes(), 'row-anatomy': rowAnatomy(),
  'app-map': appMap(), 'watch-tools': watchTools(), 'plain-english': plainEnglish(),
  'contain': contain(), 'shields-up': shieldsUp(), 'be-my-guest': beMyGuest(),
  'privacy': privacy(), 'safety': safety(), 'lineage': lineage(),
};

const outDir = new URL('./infographics/', import.meta.url).pathname
  .replace(/^\/([A-Za-z]):/, '$1:'); // deno on windows: /C:/... -> C:/...
for (const [name, svg] of Object.entries(files)) {
  await Deno.writeTextFile(outDir + name + '.svg', svg);
  console.log('wrote', name + '.svg', svg.length, 'bytes');
}
console.log('done: ' + Object.keys(files).length + ' infographics');
