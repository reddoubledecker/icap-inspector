'use strict';
// ICAP Inspector — speaks ICAP (RFC 3507) directly to any ICAP server and streams every protocol step to the browser as NDJSON. No dependencies: `node server.js`.

const http = require('http');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = Number(process.env.PORT) || 8090;
const BIND = process.env.BIND || '127.0.0.1';
const MAX_UPLOAD = (Number(process.env.MAX_UPLOAD_MB) || 200) * 1024 * 1024;
const WRITE_CHUNK = 64 * 1024;
const PREVIEW_BYTES = 4096;
const UA = 'ICAP-Inspector/1.0';
const CRLF = '\r\n';
const EMPTY = Buffer.alloc(0);

// ---------------------------------------------------------------- sample payloads

// Split so this source file itself is not flagged by local AV.
const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'latin1');

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let k = 0; k < 8; k++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Minimal "stored" (uncompressed) ZIP writer.
function makeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, 'latin1');
    const crc = crc32(f.data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x21, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(f.data.length, 18); lh.writeUInt32LE(f.data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, f.data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(f.data.length, 20); ch.writeUInt32LE(f.data.length, 24);
    ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);
    offset += 30 + name.length + f.data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

// A complete, loadable PE32 console program whose only code is `xor eax, eax; ret` (exits with code 0).
// Layout: headers in the first 0x200 bytes, one .text section at file offset 0x200 / RVA 0x1000.
function harmlessExe() {
  const b = Buffer.alloc(0x400);
  // DOS header + standard stub
  b.write('MZ', 0, 'latin1');
  b.writeUInt16LE(0x90, 0x02);   // e_cblp
  b.writeUInt16LE(3, 0x04);      // e_cp
  b.writeUInt16LE(4, 0x08);      // e_cparhdr
  b.writeUInt16LE(0xffff, 0x0c); // e_maxalloc
  b.writeUInt16LE(0xb8, 0x10);   // e_sp
  b.writeUInt16LE(0x40, 0x18);   // e_lfarlc
  b.writeUInt32LE(0x80, 0x3c);   // e_lfanew
  Buffer.from([0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21]).copy(b, 0x40);
  b.write('This program cannot be run in DOS mode.\r\r\n$', 0x4e, 'latin1');
  // PE signature + COFF header
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(0x014c, 0x84);     // Machine: i386
  b.writeUInt16LE(1, 0x86);          // NumberOfSections
  b.writeUInt32LE(0x66000000, 0x88); // TimeDateStamp (fixed for a stable hash)
  b.writeUInt16LE(0xe0, 0x94);       // SizeOfOptionalHeader
  b.writeUInt16LE(0x0103, 0x96);     // RELOCS_STRIPPED | EXECUTABLE_IMAGE | 32BIT_MACHINE
  // Optional header (PE32)
  const o = 0x98;
  b.writeUInt16LE(0x10b, o);           // Magic
  b.writeUInt8(14, o + 2);             // MajorLinkerVersion
  b.writeUInt32LE(0x200, o + 4);       // SizeOfCode
  b.writeUInt32LE(0x1000, o + 16);     // AddressOfEntryPoint
  b.writeUInt32LE(0x1000, o + 20);     // BaseOfCode
  b.writeUInt32LE(0x2000, o + 24);     // BaseOfData
  b.writeUInt32LE(0x400000, o + 28);   // ImageBase
  b.writeUInt32LE(0x1000, o + 32);     // SectionAlignment
  b.writeUInt32LE(0x200, o + 36);      // FileAlignment
  b.writeUInt16LE(6, o + 40);          // MajorOperatingSystemVersion
  b.writeUInt16LE(6, o + 48);          // MajorSubsystemVersion
  b.writeUInt32LE(0x2000, o + 56);     // SizeOfImage
  b.writeUInt32LE(0x200, o + 60);      // SizeOfHeaders
  b.writeUInt16LE(3, o + 68);          // Subsystem: Windows console
  b.writeUInt16LE(0x8100, o + 70);     // DllCharacteristics: NX_COMPAT | TERMINAL_SERVER_AWARE
  b.writeUInt32LE(0x100000, o + 72);   // SizeOfStackReserve
  b.writeUInt32LE(0x1000, o + 76);     // SizeOfStackCommit
  b.writeUInt32LE(0x100000, o + 80);   // SizeOfHeapReserve
  b.writeUInt32LE(0x1000, o + 84);     // SizeOfHeapCommit
  b.writeUInt32LE(16, o + 92);         // NumberOfRvaAndSizes (all directories empty)
  // Section table: .text
  const s = o + 0xe0;
  b.write('.text', s, 'latin1');
  b.writeUInt32LE(0x50, s + 8);        // VirtualSize (code + marker string)
  b.writeUInt32LE(0x1000, s + 12);     // VirtualAddress
  b.writeUInt32LE(0x200, s + 16);      // SizeOfRawData
  b.writeUInt32LE(0x200, s + 20);      // PointerToRawData
  b.writeUInt32LE(0x60000020, s + 36); // CODE | EXECUTE | READ
  // .text: xor eax, eax; ret — followed by a marker string so the file explains itself in a hex dump
  Buffer.from([0x31, 0xc0, 0xc3]).copy(b, 0x200);
  b.write('ICAP Inspector test program - harmless, exits immediately.', 0x210, 'latin1');
  return b;
}

const DLP_TEXT = [
  'Customer export - TEST DATA ONLY (public test numbers)',
  'name,card_number,ssn,email',
  'Jane Doe,4111 1111 1111 1111,078-05-1120,jane.doe@example.com',
  'John Roe,5500 0000 0000 0004,219-09-9999,john.roe@example.com',
  'Amex Test,3782 822463 10005,457-55-5462,amex.test@example.com',
  '',
].join('\n');

const eicarZip = makeZip([{ name: 'eicar.com', data: EICAR }]);
const SAMPLES = [
  { id: 'clean', name: 'clean.txt', mime: 'text/plain', expect: 'allow', desc: 'Harmless text file',
    data: Buffer.from('Hello from ICAP Inspector. This is a harmless text file.\n') },
  { id: 'eicar', name: 'eicar.com', mime: 'application/octet-stream', expect: 'block', desc: 'EICAR standard AV test string',
    data: EICAR },
  { id: 'eicar-zip', name: 'eicar.zip', mime: 'application/zip', expect: 'block', desc: 'EICAR inside a ZIP',
    data: eicarZip },
  { id: 'eicar-nested', name: 'eicar-nested.zip', mime: 'application/zip', expect: 'block', desc: 'EICAR three ZIP levels deep',
    data: makeZip([{ name: 'level2.zip', data: makeZip([{ name: 'level3.zip', data: eicarZip }]) }]) },
  { id: 'mismatch', name: 'invoice.pdf', mime: 'application/pdf', expect: 'policy', desc: 'Real (harmless) Windows EXE disguised as .pdf — file-type verification',
    data: harmlessExe() },
  { id: 'dlp', name: 'customers.csv', mime: 'text/csv', expect: 'policy', desc: 'Test card numbers + SSNs — DLP',
    data: Buffer.from(DLP_TEXT) },
  { id: 'large', name: 'large-clean.txt', mime: 'text/plain', expect: 'allow', desc: '10 MB clean text — size limits, preview, throughput',
    data: Buffer.alloc(10 * 1024 * 1024, 'The quick brown fox jumps over the lazy dog. 0123456789\n') },
];

// ---------------------------------------------------------------- helpers

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const fmtMs = (ms) => (ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`);
const getH = (headers, name) => {
  const h = headers.find(([k]) => k.toLowerCase() === name.toLowerCase());
  return h ? h[1] : undefined;
};

function previewOf(buf, max = PREVIEW_BYTES) {
  const s = buf.subarray(0, max);
  let ctrl = 0;
  for (const c of s) if (c === 0 || (c < 32 && c !== 9 && c !== 10 && c !== 13)) ctrl++;
  if (ctrl > s.length * 0.05) {
    const lines = [];
    const h = s.subarray(0, 512);
    for (let i = 0; i < h.length; i += 16) {
      const row = h.subarray(i, i + 16);
      const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
      const asc = [...row].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${i.toString(16).padStart(8, '0')}  ${hex}  ${asc}`);
    }
    if (buf.length > h.length) lines.push(`… ${fmtBytes(buf.length - h.length)} more`);
    return { type: 'hex', text: lines.join('\n') };
  }
  return { type: 'text', text: s.toString('utf8') + (buf.length > max ? `\n… (${fmtBytes(buf.length - max)} more)` : '') };
}

// Walks the local file headers of a (stored) ZIP and renders its tree, recursing into nested ZIPs.
function zipTree(buf, indent = '', depth = 0) {
  const lines = [];
  let off = 0;
  while (off + 30 <= buf.length && buf.readUInt32LE(off) === 0x04034b50) {
    const method = buf.readUInt16LE(off + 8);
    const size = buf.readUInt32LE(off + 18);
    const nameLen = buf.readUInt16LE(off + 26);
    const extraLen = buf.readUInt16LE(off + 28);
    const name = buf.toString('latin1', off + 30, off + 30 + nameLen);
    const start = off + 30 + nameLen + extraLen;
    const data = buf.subarray(start, start + size);
    lines.push(`${indent}└─ ${name}  (${fmtBytes(size)}${method === 0 ? ', stored' : ', compressed'})`);
    if (method === 0 && /\.zip$/i.test(name) && depth < 8) {
      lines.push(...zipTree(data, `${indent}   `, depth + 1));
    } else if (method === 0) {
      lines.push(...previewOf(data, 256).text.split('\n').map((l) => `${indent}      ${l}`));
    }
    off = start + size;
  }
  return lines;
}

function chunkify(buf) {
  return Buffer.concat([Buffer.from(buf.length.toString(16) + CRLF, 'latin1'), buf, Buffer.from(CRLF, 'latin1')]);
}

function write(sock, data) {
  return new Promise((resolve, reject) => sock.write(data, (e) => (e ? reject(e) : resolve())));
}

async function writeBody(sock, buf) {
  let n = 0;
  for (let i = 0; i < buf.length; i += WRITE_CHUNK) {
    await write(sock, chunkify(buf.subarray(i, i + WRITE_CHUNK)));
    n++;
  }
  return n;
}

// Buffered reader over a socket with "read until delimiter" / "read N bytes".
class Reader {
  constructor(sock) {
    this.chunks = [];
    this.len = 0;
    this.done = false;
    this.err = null;
    this.waiter = null;
    sock.on('data', (d) => { this.chunks.push(d); this.len += d.length; this._wake(); });
    sock.on('end', () => { this.done = true; this._wake(); });
    sock.on('close', () => { this.done = true; this._wake(); });
    sock.on('error', (e) => { this.err = e; this._wake(); });
  }
  _wake() { const w = this.waiter; this.waiter = null; if (w) w(); }
  _wait() { return new Promise((r) => { this.waiter = r; }); }
  _flat() {
    if (this.chunks.length > 1) this.chunks = [Buffer.concat(this.chunks, this.len)];
    return this.chunks[0] || EMPTY;
  }
  _take(n) {
    const b = this._flat();
    const out = b.subarray(0, n);
    const rest = b.subarray(n);
    this.chunks = rest.length ? [rest] : [];
    this.len = rest.length;
    return out;
  }
  _check() {
    if (this.err) throw this.err;
    if (this.done) throw new Error('ICAP server closed the connection');
  }
  async until(delim) {
    for (;;) {
      const i = this._flat().indexOf(delim);
      if (i >= 0) return this._take(i + delim.length);
      this._check();
      await this._wait();
    }
  }
  async bytes(n) {
    for (;;) {
      if (this.len >= n) return this._take(n);
      this._check();
      await this._wait();
    }
  }
}

async function readIcapHead(rd) {
  const headRaw = (await rd.until('\r\n\r\n')).toString('latin1');
  const [statusLine, ...lines] = headRaw.replace(/\r\n\r\n$/, '').split('\r\n');
  const m = statusLine.match(/^ICAP\/(\d+\.\d+)\s+(\d{3})\s*(.*)$/);
  if (!m) throw new Error(`Malformed ICAP status line: ${statusLine.slice(0, 200)}`);
  const headers = lines.map((l) => {
    const i = l.indexOf(':');
    return i < 0 ? [l, ''] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
  });
  return { status: Number(m[2]), reason: m[3], statusLine, headers, headRaw };
}

function parseEncapsulated(v) {
  if (!v) return [];
  return v.split(',').map((p) => {
    const [name, off] = p.trim().split('=');
    return { name: name.trim().toLowerCase(), offset: parseInt(off, 10) };
  });
}

async function readChunked(rd) {
  const parts = [];
  let chunks = 0;
  for (;;) {
    const line = (await rd.until('\r\n')).toString('latin1').trim();
    const size = parseInt(line.split(';')[0].trim(), 16);
    if (Number.isNaN(size)) throw new Error(`Bad chunk-size line: ${line.slice(0, 100)}`);
    if (size === 0) {
      for (;;) if ((await rd.until('\r\n')).length === 2) break; // skip trailers
      break;
    }
    parts.push(await rd.bytes(size));
    await rd.bytes(2);
    chunks++;
  }
  return { body: Buffer.concat(parts), chunks };
}

async function readEncapsulated(rd, resp) {
  const enc = parseEncapsulated(getH(resp.headers, 'Encapsulated'));
  const sections = {};
  let body = null;
  let bodyType = null;
  let chunks = 0;
  for (let i = 0; i < enc.length; i++) {
    const { name, offset } = enc[i];
    if (name.endsWith('-body')) {
      bodyType = name;
      if (name !== 'null-body') ({ body, chunks } = await readChunked(rd));
      break;
    }
    const next = enc[i + 1];
    if (!next) throw new Error(`Encapsulated header has no body entry after ${name}`);
    sections[name] = (await rd.bytes(next.offset - offset)).toString('latin1');
  }
  return { sections, body, bodyType, chunks };
}

function httpContentType(sectionText) {
  const m = (sectionText || '').match(/^content-type:\s*([^\r\n]+)/im);
  return m ? m[1].trim() : null;
}

// ---------------------------------------------------------------- transactions

function connect(cfg, ev) {
  return new Promise((resolve, reject) => {
    ev({ kind: 'send', title: `${cfg.tls ? 'TLS' : 'TCP'} connect → ${cfg.host}:${cfg.port}` });
    const onErr = (e) => reject(e);
    let s;
    if (cfg.tls) {
      s = tls.connect({
        host: cfg.host, port: cfg.port, rejectUnauthorized: !cfg.insecure,
        servername: net.isIP(cfg.host) ? undefined : cfg.host,
      }, () => {
        const c = s.getPeerCertificate();
        const f = (o) => Object.entries(o || {}).map(([k, v]) => `${k}=${v}`).join(', ');
        ev({
          kind: 'recv', tone: s.authorized ? 'ok' : 'warn',
          title: `TLS established · ${s.getProtocol()}`,
          raw: [
            `Protocol: ${s.getProtocol()}`, `Cipher:   ${s.getCipher().name}`,
            `Subject:  ${f(c.subject)}`, `Issuer:   ${f(c.issuer)}`,
            `Valid:    ${c.valid_from} → ${c.valid_to}`,
            `Trusted:  ${s.authorized ? 'yes' : `no (${s.authorizationError})`}`,
          ].join('\n'),
        });
        s.off('error', onErr);
        resolve(s);
      });
    } else {
      s = net.connect({ host: cfg.host, port: cfg.port }, () => {
        ev({ kind: 'recv', tone: 'ok', title: 'TCP connection established' });
        s.off('error', onErr);
        resolve(s);
      });
    }
    s.once('error', onErr);
    s.setTimeout(cfg.timeout * 1000, () => s.destroy(new Error(`Connect timed out after ${cfg.timeout}s`)));
  });
}

async function transaction(cfg, emit, fn) {
  const t0 = performance.now();
  const clock = () => Math.round((performance.now() - t0) * 10) / 10;
  const ev = (o) => emit({ t: clock(), ...o });
  let sock;
  try {
    sock = await connect(cfg, ev);
    const rd = new Reader(sock);
    sock.setTimeout(cfg.timeout * 1000, () => sock.destroy(new Error(`No activity for ${cfg.timeout}s — timed out`)));
    const result = await fn(sock, rd, ev, clock);
    ev({ kind: 'info', title: `Done · ${fmtMs(clock())}` });
    return { kind: 'done', totalMs: clock(), ...result };
  } catch (e) {
    ev({ kind: 'error', title: e.message || String(e) });
    return { kind: 'done', totalMs: clock(), verdict: { code: 'error', label: 'Failed', reason: e.message || String(e) } };
  } finally {
    if (sock) sock.destroy();
  }
}

const icapUri = (cfg, service) => `icap://${cfg.host}:${cfg.port}/${service}`;

function runOptions(cfg, emit) {
  return transaction(cfg, emit, async (sock, rd, ev, clock) => {
    const uri = icapUri(cfg, cfg.service);
    const head = [`OPTIONS ${uri} ICAP/1.0`, `Host: ${cfg.host}`, `User-Agent: ${UA}`, ...cfg.extraHeaders,
      'Encapsulated: null-body=0'].join(CRLF) + CRLF + CRLF;
    await write(sock, Buffer.from(head, 'latin1'));
    ev({ kind: 'send', title: `OPTIONS /${cfg.service}`, raw: head });
    const tWait = clock();
    ev({ kind: 'wait', title: 'waiting for OPTIONS response' });
    const resp = await readIcapHead(rd);
    const serverMs = clock() - tWait;
    const enc = await readEncapsulated(rd, resp);
    ev({
      kind: 'recv', tone: resp.status === 200 ? 'ok' : 'bad', title: resp.statusLine.replace(/^ICAP\/\S+\s+/, ''),
      raw: resp.headRaw + (enc.body ? `[opt-body: ${fmtBytes(enc.body.length)}]` : ''),
    });
    return {
      type: 'options', uri,
      icap: { status: resp.status, reason: resp.reason, statusLine: resp.statusLine, headers: resp.headers },
      timings: { serverMs },
      verdict: resp.status === 200
        ? { code: 'ok', label: 'Service reachable', reason: `Methods: ${getH(resp.headers, 'Methods') || '?'} · Preview: ${getH(resp.headers, 'Preview') || 'n/a'} · ISTag: ${getH(resp.headers, 'ISTag') || 'n/a'}` }
        : { code: 'error', label: `ICAP ${resp.status}`, reason: resp.reason || 'OPTIONS request was rejected — check the service name.' },
    };
  });
}

function buildEncapsulated(cfg, p) {
  const raw = cfg.url.replace('{name}', encodeURIComponent(p.name));
  let u;
  try { u = new URL(raw); } catch { throw new Error(`Simulated URL is not a valid absolute URL: ${raw}`); }
  const safeName = p.name.replace(/[^\x20-\x7e]|"/g, '_');
  const ua = 'User-Agent: Mozilla/5.0 (ICAP Inspector)';
  if (cfg.mode === 'RESPMOD') {
    const req = `GET ${u.href} HTTP/1.1${CRLF}Host: ${u.host}${CRLF}${ua}${CRLF}Accept: */*${CRLF}${CRLF}`;
    const res = `HTTP/1.1 200 OK${CRLF}Content-Type: ${p.mime}${CRLF}Content-Length: ${p.data.length}${CRLF}` +
      `Content-Disposition: attachment; filename="${safeName}"${CRLF}${CRLF}`;
    const bodyTag = p.data.length ? 'res-body' : 'null-body';
    return { parts: [req, res], encap: `req-hdr=0, res-hdr=${req.length}, ${bodyTag}=${req.length + res.length}`, body: p.data.length ? p.data : null };
  }
  if (!p.data.length) {
    const req = `GET ${u.href} HTTP/1.1${CRLF}Host: ${u.host}${CRLF}${ua}${CRLF}${CRLF}`;
    return { parts: [req], encap: `req-hdr=0, null-body=${req.length}`, body: null };
  }
  let body = p.data;
  let ctype = p.mime;
  if (cfg.uploadEncoding === 'multipart') {
    const b = `----ICAPInspector${crypto.randomBytes(8).toString('hex')}`;
    body = Buffer.concat([
      Buffer.from(`--${b}${CRLF}Content-Disposition: form-data; name="file"; filename="${safeName}"${CRLF}Content-Type: ${p.mime}${CRLF}${CRLF}`, 'latin1'),
      p.data,
      Buffer.from(`${CRLF}--${b}--${CRLF}`, 'latin1'),
    ]);
    ctype = `multipart/form-data; boundary=${b}`;
  }
  const req = `POST ${u.href} HTTP/1.1${CRLF}Host: ${u.host}${CRLF}${ua}${CRLF}Content-Type: ${ctype}${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}`;
  return { parts: [req], encap: `req-hdr=0, req-body=${req.length}`, body };
}

function classify(mode, resp, enc, sentBody) {
  if (resp.status === 204) {
    return { code: 'allow', label: 'Allowed', reason: '204 No Content — the server did not modify anything; the original message passes through untouched.' };
  }
  if (resp.status !== 200) {
    return { code: 'error', label: `ICAP ${resp.status}`, reason: resp.reason || 'The ICAP server returned an error status.' };
  }
  const resHdr = enc.sections['res-hdr'];
  const m = resHdr && resHdr.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  const httpStatus = m ? Number(m[1]) : null;
  if (mode === 'REQMOD' && resHdr) {
    return { code: 'block', label: 'Blocked', httpStatus, reason: `The server answered the upload with an HTTP ${httpStatus || ''} response instead of forwarding it — the request never reaches the web server.` };
  }
  if (httpStatus && httpStatus >= 400) {
    return { code: 'block', label: 'Blocked', httpStatus, reason: `The download was replaced with an HTTP ${httpStatus} response (block page).` };
  }
  if (!sentBody && !enc.body) return { code: 'allow', label: 'Allowed', reason: '200 OK — request allowed (headers only).' };
  if (sentBody && enc.body && enc.body.equals(sentBody)) {
    return { code: 'allow', label: 'Allowed', reason: '200 OK with the original content returned byte-for-byte unchanged.' };
  }
  if (!enc.body) return { code: 'modified', label: 'Modified', reason: 'The server removed the body from the message.' };
  return {
    code: 'modified', label: 'Modified',
    reason: `Content was rewritten by the server (${fmtBytes(sentBody ? sentBody.length : 0)} → ${fmtBytes(enc.body.length)}) — typically content disarm (CDR) sanitization or DLP redaction.`,
  };
}

const outputs = new Map();
function storeOutput(o) {
  const id = crypto.randomUUID();
  outputs.set(id, o);
  while (outputs.size > 50) outputs.delete(outputs.keys().next().value);
  return id;
}

function bodyRaw(label, buf) {
  const p = previewOf(buf, 1024);
  return `${label}: ${fmtBytes(buf.length)} (chunked encoding)\n\n${p.text}`;
}

function runScan(cfg, payload, emit) {
  return transaction(cfg, emit, async (sock, rd, ev, clock) => {
    const mode = cfg.mode;
    const service = mode === 'REQMOD' ? cfg.reqService : cfg.respService;
    const uri = icapUri(cfg, service);
    const built = buildEncapsulated(cfg, payload);
    const body = built.body;
    const usePreview = cfg.preview != null && body;

    const lines = [
      `${mode} ${uri} ICAP/1.0`, `Host: ${cfg.host}`, `User-Agent: ${UA}`,
      cfg.allow204 && 'Allow: 204',
      usePreview && `Preview: ${cfg.preview}`,
      cfg.clientIp && `X-Client-IP: ${cfg.clientIp}`,
      cfg.user && `X-Authenticated-User: ${cfg.user}`,
      ...cfg.extraHeaders,
      `Encapsulated: ${built.encap}`,
    ].filter(Boolean);
    const icapHead = lines.join(CRLF) + CRLF + CRLF;
    const httpHeaders = built.parts.join('');
    const headBuf = Buffer.from(icapHead + httpHeaders, 'latin1');
    const headRaw = icapHead + httpHeaders;

    let complete = true;
    if (!body) {
      await write(sock, headBuf);
      ev({ kind: 'send', title: `${mode} headers · no body (${fmtBytes(headBuf.length)})`, raw: headRaw });
    } else if (!usePreview) {
      await write(sock, headBuf);
      ev({ kind: 'send', title: `${mode} headers (${fmtBytes(headBuf.length)})`, raw: headRaw });
      const n = await writeBody(sock, body);
      await write(sock, '0\r\n\r\n');
      ev({ kind: 'send', title: `Body ${fmtBytes(body.length)} · ${n} chunk${n === 1 ? '' : 's'} + 0`, raw: bodyRaw('Encapsulated body sent', body) });
    } else {
      const pv = body.subarray(0, cfg.preview);
      complete = body.length <= cfg.preview;
      await write(sock, Buffer.concat([headBuf, pv.length ? chunkify(pv) : EMPTY, Buffer.from(complete ? '0; ieof\r\n\r\n' : '0\r\n\r\n', 'latin1')]));
      ev({ kind: 'send', title: `${mode} headers (${fmtBytes(headBuf.length)})`, raw: headRaw });
      ev({
        kind: 'send',
        title: complete ? `Preview ${fmtBytes(pv.length)} + ieof (whole body)` : `Preview ${fmtBytes(pv.length)} of ${fmtBytes(body.length)}`,
        raw: bodyRaw(complete ? 'Preview (entire body, terminated with "0; ieof")' : 'Preview (terminated with "0" — server may ask for the rest)', pv),
      });
    }

    let tWait = clock();
    ev({ kind: 'wait', core: true, title: 'scanning' });
    let resp = await readIcapHead(rd);

    if (resp.status === 100) {
      if (!usePreview || complete) throw new Error('Server sent 100 Continue although there is nothing left to send');
      ev({ kind: 'recv', tone: 'info', title: '100 Continue — send the rest', raw: resp.headRaw });
      const rest = body.subarray(cfg.preview);
      const n = await writeBody(sock, rest);
      await write(sock, '0\r\n\r\n');
      ev({ kind: 'send', title: `Remaining body ${fmtBytes(rest.length)} · ${n} chunk${n === 1 ? '' : 's'} + 0`, raw: bodyRaw('Remainder sent', rest) });
      tWait = clock();
      ev({ kind: 'wait', core: true, title: 'scanning' });
      resp = await readIcapHead(rd);
    } else if (usePreview && !complete) {
      ev({ kind: 'info', title: `Server decided after the preview — the other ${fmtBytes(body.length - cfg.preview)} were never sent` });
    }
    const serverMs = clock() - tWait;

    const enc = await readEncapsulated(rd, resp);
    const verdict = classify(mode, resp, enc, body);
    const tone = { allow: 'ok', block: 'bad', modified: 'warn' }[verdict.code] || 'bad';
    ev({ kind: 'recv', tone, title: resp.statusLine.replace(/^ICAP\/\S+\s+/, ''), raw: resp.headRaw });

    const sectionText = Object.values(enc.sections).join('');
    if (sectionText || enc.body) {
      ev({
        kind: 'recv', tone,
        title: `Encapsulated ${Object.keys(enc.sections).join(' + ') || ''}${enc.body ? ` + body ${fmtBytes(enc.body.length)}` : ''}`,
        raw: sectionText + (enc.body ? bodyRaw('\nEncapsulated body received', enc.body) : ''),
      });
    }

    let received = null;
    if (enc.body) {
      const ctype = httpContentType(enc.sections['res-hdr'] || enc.sections['req-hdr']);
      const out = { body: enc.body, contentType: ctype, filename: `icap-output-${payload.name.replace(/[^\w.-]/g, '_')}` };
      const pv = previewOf(enc.body);
      received = {
        id: storeOutput(out), size: enc.body.length, sha256: sha256(enc.body), chunks: enc.chunks,
        contentType: ctype, preview: pv.text, previewType: pv.type,
      };
    }

    return {
      type: 'scan', mode, uri,
      icap: { status: resp.status, reason: resp.reason, statusLine: resp.statusLine, headers: resp.headers },
      http: enc.sections, bodyType: enc.bodyType,
      file: { name: payload.name, size: payload.data.length, sha256: sha256(payload.data) },
      sent: body ? { size: body.length, sha256: sha256(body) } : null,
      received,
      timings: { serverMs },
      verdict,
    };
  });
}

// ---------------------------------------------------------------- HTTP server

function normalizeCfg(c) {
  const s = (v) => String(v ?? '').replace(/[\r\n]/g, '').trim();
  const svc = (v) => s(v).replace(/^\/+/, '');
  const host = s(c.host);
  if (!host) throw new Error('ICAP host is required');
  const useTls = !!c.tls;
  const port = parseInt(c.port, 10) || (useTls ? 11344 : 1344);
  if (port < 1 || port > 65535) throw new Error('Port must be 1-65535');
  const preview = c.preview === '' || c.preview == null ? null : parseInt(c.preview, 10);
  if (preview != null && (Number.isNaN(preview) || preview < 0)) throw new Error('Preview must be a number ≥ 0 (or empty to disable)');
  const extraHeaders = String(c.extraHeaders || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const h of extraHeaders) if (!/^[A-Za-z0-9-]+:.*$/.test(h)) throw new Error(`Invalid extra header line: ${h}`);
  const mime = s(c.mime);
  return {
    host, port, tls: useTls, insecure: c.insecure !== false,
    timeout: Math.min(600, Math.max(1, parseInt(c.timeout, 10) || 60)),
    mode: c.mode === 'REQMOD' ? 'REQMOD' : 'RESPMOD',
    service: svc(c.service), reqService: svc(c.reqService), respService: svc(c.respService),
    preview, allow204: c.allow204 !== false,
    url: s(c.url) || 'http://lab.test/files/{name}',
    uploadEncoding: c.uploadEncoding === 'raw' ? 'raw' : 'multipart',
    clientIp: s(c.clientIp), user: s(c.user), extraHeaders,
    sample: s(c.sample), fileName: s(c.fileName) || 'upload.bin',
    mime: /^[\w.+-]+\/[\w.+-]+$/.test(mime) ? mime : 'application/octet-stream',
  };
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let n = 0;
    req.on('data', (d) => {
      n += d.length;
      if (n > limit) { reject(new Error(`Upload exceeds ${fmtBytes(limit)} (set MAX_UPLOAD_MB)`)); req.destroy(); return; }
      parts.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

async function stream(res, fn) {
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
  const emit = (o) => { if (!res.destroyed && !res.writableEnded) res.write(JSON.stringify(o) + '\n'); };
  emit(await fn(emit));
  res.end();
}

const INDEX = path.join(__dirname, 'public', 'index.html');
// Static assets served from public/ — an explicit allowlist, so nothing else in the package is reachable.
const STATIC = {
  '/logo.svg': ['logo.svg', 'image/svg+xml'],
  '/favicon.ico': ['favicon-32.png', 'image/png'],
  '/favicon-32.png': ['favicon-32.png', 'image/png'],
  '/apple-touch-icon.png': ['apple-touch-icon.png', 'image/png'],
};

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return fs.createReadStream(INDEX).pipe(res);
    }
    if (req.method === 'GET' && STATIC[u.pathname]) {
      const [file, type] = STATIC[u.pathname];
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'max-age=86400' });
      return fs.createReadStream(path.join(__dirname, 'public', file)).pipe(res);
    }
    if (req.method === 'GET' && u.pathname === '/api/samples') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify(SAMPLES.map(({ data, ...s }) => ({ ...s, size: data.length }))));
    }
    const sm = u.pathname.match(/^\/api\/samples\/([\w-]+)$/);
    if (req.method === 'GET' && sm) {
      const s = SAMPLES.find((x) => x.id === sm[1]);
      if (!s) { res.writeHead(404); return res.end('Unknown sample'); }
      const pv = previewOf(s.data);
      const tree = s.mime === 'application/zip' ? [s.name, ...zipTree(s.data)].join('\n') : null;
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({
        id: s.id, name: s.name, mime: s.mime, desc: s.desc, expect: s.expect,
        size: s.data.length, sha256: sha256(s.data), previewType: pv.type, preview: pv.text, tree,
      }));
    }
    if (req.method === 'POST' && u.pathname === '/api/options') {
      const cfg = normalizeCfg(JSON.parse((await readBody(req, 1e5)).toString() || '{}'));
      return stream(res, (emit) => runOptions(cfg, emit));
    }
    if (req.method === 'POST' && u.pathname === '/api/scan') {
      const cfg = normalizeCfg(JSON.parse(u.searchParams.get('cfg') || '{}'));
      const upload = await readBody(req, MAX_UPLOAD);
      let payload;
      if (cfg.sample) {
        const s = SAMPLES.find((x) => x.id === cfg.sample);
        if (!s) throw new Error(`Unknown sample: ${cfg.sample}`);
        payload = { name: s.name, mime: s.mime, data: s.data };
      } else {
        payload = { name: cfg.fileName, mime: cfg.mime, data: upload };
      }
      if (cfg.mode === 'RESPMOD' && !payload.data.length) throw new Error('RESPMOD needs a file or sample to scan');
      return stream(res, (emit) => runScan(cfg, payload, emit));
    }
    const m = u.pathname.match(/^\/api\/output\/([\w-]+)$/);
    if (req.method === 'GET' && m) {
      const o = outputs.get(m[1]);
      if (!o) { res.writeHead(404); return res.end('Output expired'); }
      if (u.searchParams.has('view')) {
        res.writeHead(200, {
          'Content-Type': o.contentType || 'text/plain; charset=utf-8',
          'Content-Security-Policy': 'sandbox', 'X-Content-Type-Options': 'nosniff',
        });
      } else {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${o.filename}"` });
      }
      return res.end(o.body);
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (e) {
    if (!res.headersSent) res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(e.message || String(e));
  }
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`Port ${PORT} is already in use. Pick another with --port <n> (or PORT=<n>).`);
  else if (e.code === 'EACCES') console.error(`No permission to listen on ${BIND}:${PORT}. Try a different port with --port <n>.`);
  else console.error(e.message);
  process.exit(1);
});

server.listen(PORT, BIND, () => {
  const local = `http://${BIND === '0.0.0.0' ? 'localhost' : BIND}:${PORT}`;
  console.log(`ICAP Inspector running at ${local}`);
  if (BIND === '0.0.0.0') {
    const addrs = Object.values(os.networkInterfaces()).flat().filter((a) => a && a.family === 'IPv4' && !a.internal);
    for (const a of addrs) console.log(`  also reachable at http://${a.address}:${PORT}`);
  } else if (BIND === '127.0.0.1') {
    console.log('Only reachable from this machine. Use --bind 0.0.0.0 (or BIND=0.0.0.0) to expose it on the lab network.');
  }
  server.emit('ready', local);
});

module.exports = server;
