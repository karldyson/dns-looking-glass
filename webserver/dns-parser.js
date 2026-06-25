/* dns-parser.js — DNS wire format parser for packet visualisation.
   Produces an annotated structure suitable for Wireshark-style and hex dump views.
   No external dependencies. Loaded before app.js. */

'use strict';

const DNSParser = (() => {

  // ── Public API ──────────────────────────────────────────────────────────────
  function parse(bytes) {
    const r = new Reader(bytes);
    const result = {
      header:     null,
      question:   [],
      answer:     [],
      authority:  [],
      additional: [],
      annotations: [],  // [{ start, end, field, desc, value }]
    };

    try {
      result.header     = parseHeader(r, result.annotations);
      result.question   = parseSectionQ(r, result.header.qdcount, result.annotations);
      result.answer     = parseSection(r, result.header.ancount, result.annotations);
      result.authority  = parseSection(r, result.header.nscount, result.annotations);
      result.additional = parseSection(r, result.header.arcount, result.annotations);
    } catch (e) {
      result._error = e.message;
    }

    return result;
  }

  // ── Reader ──────────────────────────────────────────────────────────────────
  class Reader {
    constructor(bytes) {
      this.buf = bytes;
      this.pos = 0;
    }
    get length() { return this.buf.length; }
    u8()  { if (this.pos >= this.buf.length) throw new Error('buffer underrun'); return this.buf[this.pos++]; }
    u16() { return (this.u8() << 8) | this.u8(); }
    u32() { return ((this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8()) >>> 0; }
    bytes(n) {
      const out = this.buf.slice(this.pos, this.pos + n);
      this.pos += n;
      return out;
    }
    mark() { return this.pos; }
    seek(pos) { this.pos = pos; }
  }

  // ── Header ──────────────────────────────────────────────────────────────────
  function parseHeader(r, ann) {
    const start = r.mark(); // 0
    const id    = r.u16();
    const flags = r.u16();
    const qd    = r.u16();
    const an    = r.u16();
    const ns    = r.u16();
    const ar    = r.u16();

    const qr     = (flags >> 15) & 1;
    const opcode = (flags >> 11) & 0xf;
    const aa     = (flags >> 10) & 1;
    const tc     = (flags >>  9) & 1;
    const rd     = (flags >>  8) & 1;
    const ra     = (flags >>  7) & 1;
    const z      = (flags >>  6) & 1;
    const ad     = (flags >>  5) & 1;
    const cd     = (flags >>  4) & 1;
    const rcode  = flags & 0xf;

    const opcodeNames = ['QUERY','IQUERY','STATUS','','NOTIFY','UPDATE'];
    const rcodeNames  = ['NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED',
                         'YXDOMAIN','YXRRSET','NXRRSET','NOTAUTH','NOTZONE'];

    // Annotate individual flag bytes for cross-highlight.
    ann.push({ start: 2, end: 4, field: 'Flags', value: `0x${flags.toString(16).padStart(4,'0')}` });
    ann.push({ start: 0, end: 2, field: 'ID', value: `0x${id.toString(16).padStart(4,'0')} (${id})` });
    ann.push({ start: 4, end: 6, field: 'QDCOUNT', value: qd });
    ann.push({ start: 6, end: 8, field: 'ANCOUNT', value: an });
    ann.push({ start: 8, end: 10, field: 'NSCOUNT', value: ns });
    ann.push({ start: 10, end: 12, field: 'ARCOUNT', value: ar });

    const flagsChildren = [
      bitRow(2, 15, 15, qr,     'QR',     qr ? 'Response' : 'Query'),
      bitRow(2, 14, 11, opcode, 'Opcode', opcodeNames[opcode] ?? `${opcode}`),
      bitRow(2, 10, 10, aa,     'AA',     aa ? 'Authoritative' : 'Not Authoritative'),
      bitRow(2,  9,  9, tc,     'TC',     tc ? 'Truncated' : 'Not Truncated'),
      bitRow(2,  8,  8, rd,     'RD',     rd ? 'Recursion Desired' : 'Recursion Not Desired'),
      bitRow(3,  7,  7, ra,     'RA',     ra ? 'Recursion Available' : 'Recursion Not Available'),
      bitRow(3,  6,  6, z,      'Z',      'Reserved'),
      bitRow(3,  5,  5, ad,     'AD',     ad ? 'Authentic Data' : 'Not Authentic Data'),
      bitRow(3,  4,  4, cd,     'CD',     cd ? 'Checking Disabled' : 'Checking Not Disabled'),
      bitRow(3,  3,  0, rcode,  'RCODE',  rcodeNames[rcode] ?? `${rcode}`),
    ];

    return {
      start, end: 12,
      label: 'DNS Header',
      id, flags, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode,
      qdcount: qd, ancount: an, nscount: ns, arcount: ar,
      children: [
        { start: 0, end: 2, field: 'Transaction ID', value: `0x${id.toString(16).padStart(4,'0')} (${id})` },
        {
          label: `Flags: 0x${flags.toString(16).padStart(4,'0')}`,
          start: 2, end: 4,
          children: flagsChildren,
        },
        { start: 4, end: 6,  field: 'Questions',        value: qd },
        { start: 6, end: 8,  field: 'Answer RRs',       value: an },
        { start: 8, end: 10, field: 'Authority RRs',     value: ns },
        { start: 10, end: 12, field: 'Additional RRs',  value: ar },
      ],
    };
  }

  function bitRow(byteIdx, hi, lo, val, name, desc) {
    // Build Wireshark-style bit pattern string: "1... .... = QR: Response"
    const totalBits = 16;
    let pattern = '';
    for (let b = 15; b >= 0; b--) {
      if (b !== 15 && b % 4 === 3) pattern += ' ';
      if (b > hi || b < lo) {
        pattern += '.';
      } else if (hi === lo) {
        pattern += val ? '1' : '0';
      } else {
        // multi-bit field — show value in binary
        const bit = (val >> (b - lo)) & 1;
        pattern += bit;
      }
    }
    return {
      start: byteIdx,
      end:   byteIdx + 1,
      bits:  pattern,
      field: name,
      desc,
    };
  }

  // ── Question section ────────────────────────────────────────────────────────
  function parseSectionQ(r, count, ann) {
    const items = [];
    for (let i = 0; i < count; i++) {
      const start = r.mark();
      const name = parseName(r, r.buf);
      const qtype  = r.u16();
      const qclass = r.u16();
      const end = r.mark();
      ann.push({ start, end, field: 'Question', value: `${name} ${typeStr(qtype)} ${classStr(qclass)}` });
      items.push({
        start, end,
        children: [
          { start, end: end - 4, field: 'Name',   value: name },
          { start: end - 4, end: end - 2, field: 'Type',  value: typeStr(qtype) },
          { start: end - 2, end,          field: 'Class', value: classStr(qclass) },
        ],
        label: `${name} ${typeStr(qtype)}`,
      });
    }
    return items;
  }

  // ── Resource record sections ────────────────────────────────────────────────
  function parseSection(r, count, ann) {
    const items = [];
    for (let i = 0; i < count; i++) {
      try {
        const rr = parseRR(r, ann);
        if (rr) items.push(rr);
      } catch (e) {
        break;
      }
    }
    return items;
  }

  function parseRR(r, ann) {
    const start = r.mark();
    const name  = parseName(r, r.buf);
    const type  = r.u16();
    const cls   = r.u16();
    const ttl   = r.u32();
    const rdlen = r.u16();
    const rdstart = r.mark();
    const rdata = parseRDATA(r, type, rdlen, r.buf);
    r.seek(rdstart + rdlen);
    const end = r.mark();

    let children;
    if (type === 41) {
      // OPT RR: Class = UDP payload size; TTL = extended RCODE (8b) | version (8b) | Z+DO (16b)
      const udpSize  = cls;
      const extRcode = (ttl >>> 24) & 0xFF;
      const ednsVer  = (ttl >>> 16) & 0xFF;
      const doBit    = (ttl >>> 15) & 1;
      children = [
        { start, end: rdstart - 10, field: 'Name', value: name },
        { start: rdstart - 10, end: rdstart - 8, field: 'Type', value: 'OPT' },
        { start: rdstart - 8,  end: rdstart - 6, field: 'UDP Payload Size', value: udpSize },
        {
          label: `Extended RCODE and Flags: 0x${ttl.toString(16).padStart(8, '0')}`,
          start: rdstart - 6, end: rdstart - 2,
          children: [
            { start: rdstart - 6, end: rdstart - 5, field: 'Extended RCODE', value: extRcode },
            { start: rdstart - 5, end: rdstart - 4, field: 'EDNS Version',   value: ednsVer },
            { start: rdstart - 4, end: rdstart - 2,
              bits:  doBit ? '1... .... .... ....' : '0... .... .... ....',
              field: 'DO', desc: doBit ? 'DNSSEC OK' : 'DNSSEC not OK' },
          ],
        },
        { start: rdstart - 2, end: rdstart, field: 'RDLENGTH', value: rdlen },
        ...rdata,
      ];
    } else {
      children = [
        { start, end: rdstart - 10, field: 'Name',  value: name },
        { start: rdstart - 10, end: rdstart - 8, field: 'Type',  value: typeStr(type) },
        { start: rdstart - 8,  end: rdstart - 6, field: 'Class', value: classStr(cls) },
        { start: rdstart - 6,  end: rdstart - 2, field: 'TTL',   value: `${ttl}s` },
        { start: rdstart - 2,  end: rdstart,     field: 'RDLENGTH', value: rdlen },
        ...rdata,
      ];
    }

    ann.push({ start, end, field: typeStr(type), value: name });

    return { start, end, label: type === 41 ? 'OPT (EDNS)' : `${name} ${typeStr(type)}`, children };
  }

  // ── RDATA parsers ───────────────────────────────────────────────────────────
  function parseRDATA(r, type, rdlen, buf) {
    const start = r.mark();

    const row = (field, value, extra) => ({ start, end: r.mark(), field, value, ...extra });

    switch (type) {
      case 1: { // A
        const b = r.bytes(4);
        return [{ start, end: r.mark(), field: 'Address', value: [...b].join('.') }];
      }
      case 28: { // AAAA
        const b = r.bytes(16);
        const groups = [];
        for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i+1]).toString(16));
        return [{ start, end: r.mark(), field: 'Address', value: groups.join(':') }];
      }
      case 2: case 5: case 12: case 39: { // NS, CNAME, PTR, DNAME
        const name = parseName(r, buf);
        return [{ start, end: r.mark(), field: typeStr(type), value: name }];
      }
      case 15: { // MX
        const pref = r.u16();
        const name = parseName(r, buf);
        return [
          { start, end: start + 2, field: 'Preference', value: pref },
          { start: start + 2, end: r.mark(), field: 'Exchange', value: name },
        ];
      }
      case 6: { // SOA
        const mname   = parseName(r, buf);
        const p1 = r.mark();
        const rname   = parseName(r, buf);
        const p2 = r.mark();
        const serial  = r.u32();
        const refresh = r.u32();
        const retry   = r.u32();
        const expire  = r.u32();
        const minimum = r.u32();
        return [
          { start,   end: p1,   field: 'MNAME',   value: mname },
          { start: p1, end: p2, field: 'RNAME',   value: rname.replace(/^(.+?)\./, '$1@') },
          { start: p2,       end: p2+4,  field: 'Serial',  value: serial },
          { start: p2+4,     end: p2+8,  field: 'Refresh', value: `${refresh}s` },
          { start: p2+8,     end: p2+12, field: 'Retry',   value: `${retry}s` },
          { start: p2+12,    end: p2+16, field: 'Expire',  value: `${expire}s` },
          { start: p2+16,    end: p2+20, field: 'Minimum', value: `${minimum}s` },
        ];
      }
      case 16: { // TXT
        const rows = [];
        let pos = start;
        while (r.mark() < start + rdlen) {
          const len = r.u8();
          const tb  = r.bytes(len);
          const txt = String.fromCharCode(...tb);
          rows.push({ start: pos, end: r.mark(), field: 'String', value: `"${txt}"` });
          pos = r.mark();
        }
        return rows;
      }
      case 43: { // DS
        const tag  = r.u16();
        const alg  = r.u8();
        const dtyp = r.u8();
        const dlen = rdlen - 4;
        const dig  = r.bytes(dlen);
        return [
          { start,     end: start+2, field: 'Key Tag',   value: tag },
          { start: start+2, end: start+3, field: 'Algorithm', value: algStr(alg) },
          { start: start+3, end: start+4, field: 'Digest Type', value: digestTypeStr(dtyp) },
          { start: start+4, end: r.mark(), field: 'Digest', value: bytesHex(dig) },
        ];
      }
      case 48: { // DNSKEY
        const flags = r.u16();
        const proto = r.u8();
        const alg   = r.u8();
        const key   = r.bytes(rdlen - 4);
        const zoneKey = (flags >> 8) & 1;
        const sep     = flags & 1;
        return [
          { start,     end: start+2, field: 'Flags', value: `0x${flags.toString(16).padStart(4,'0')} (Zone Key: ${zoneKey ? 'yes':'no'}, SEP: ${sep ? 'yes':'no'})` },
          { start: start+2, end: start+3, field: 'Protocol', value: proto },
          { start: start+3, end: start+4, field: 'Algorithm', value: algStr(alg) },
          { start: start+4, end: r.mark(), field: 'Public Key', value: `[${key.length} bytes]` },
        ];
      }
      case 46: { // RRSIG
        const typeCov = r.u16();
        const alg     = r.u8();
        const labels  = r.u8();
        const origTTL = r.u32();
        const sigExp  = r.u32();
        const sigInc  = r.u32();
        const keyTag  = r.u16();
        const signer  = parseName(r, buf);
        const sig     = r.bytes(rdlen - (r.mark() - start));
        return [
          { start,      end: start+2,  field: 'Type Covered', value: typeStr(typeCov) },
          { start: start+2,  end: start+3,  field: 'Algorithm',   value: algStr(alg) },
          { start: start+3,  end: start+4,  field: 'Labels',      value: labels },
          { start: start+4,  end: start+8,  field: 'Orig TTL',    value: `${origTTL}s` },
          { start: start+8,  end: start+12, field: 'Sig Expiration', value: tsStr(sigExp) },
          { start: start+12, end: start+16, field: 'Sig Inception',  value: tsStr(sigInc) },
          { start: start+16, end: start+18, field: 'Key Tag',      value: keyTag },
          { start: start+18, end: start+18+signer.length+2, field: 'Signer', value: signer },
          { start: r.mark() - sig.length, end: r.mark(), field: 'Signature', value: `[${sig.length} bytes]` },
        ];
      }
      case 47: { // NSEC
        const next = parseName(r, buf);
        const bitmapBytes = r.bytes(rdlen - (r.mark() - start));
        return [
          { start, end: start + (r.mark() - start - bitmapBytes.length), field: 'Next Domain', value: next },
          { start: r.mark() - bitmapBytes.length, end: r.mark(), field: 'Type Bitmap', value: decodeBitmap(bitmapBytes) },
        ];
      }
      case 50: { // NSEC3
        const alg    = r.u8();
        const flags  = r.u8();
        const iter   = r.u16();
        const slen   = r.u8();
        const salt   = r.bytes(slen);
        const hlen   = r.u8();
        const hash   = r.bytes(hlen);
        const bitmap = r.bytes(rdlen - (r.mark() - start));
        return [
          { start,      end: start+1, field: 'Hash Algorithm', value: algStr(alg) },
          { start: start+1, end: start+2, field: 'Flags',      value: flags },
          { start: start+2, end: start+4, field: 'Iterations', value: iter },
          { start: start+5, end: start+5+slen, field: 'Salt', value: slen ? bytesHex(salt) : '-' },
          { start: start+6+slen, end: start+6+slen+hlen, field: 'Next Hashed Owner', value: bytesHex(hash) },
          { start: r.mark() - bitmap.length, end: r.mark(), field: 'Type Bitmap', value: decodeBitmap(bitmap) },
        ];
      }
      case 257: { // CAA
        const critFlag = r.u8();
        const tagLen   = r.u8();
        const tag      = String.fromCharCode(...r.bytes(tagLen));
        const val      = String.fromCharCode(...r.bytes(rdlen - 2 - tagLen));
        return [
          { start,      end: start+1, field: 'Flags', value: critFlag },
          { start: start+1, end: start+2, field: 'Tag Length', value: tagLen },
          { start: start+2, end: start+2+tagLen, field: 'Tag', value: tag },
          { start: start+2+tagLen, end: r.mark(), field: 'Value', value: val },
        ];
      }
      case 41: { // OPT (EDNS)
        const rows = [];
        const endPos = start + rdlen;
        while (r.mark() < endPos) {
          const optStart = r.mark();
          const optCode  = r.u16();
          const optLen   = r.u16();
          const optData  = r.bytes(optLen);
          rows.push(decodeEdnsOpt(optCode, optData, optStart, r.mark()));
        }
        return rows;
      }
      default: {
        r.bytes(rdlen);
        return [{ start, end: r.mark(), field: 'RDATA', value: `[${rdlen} bytes — type ${typeStr(type)}]` }];
      }
    }
  }

  // ── Name parsing (with compression pointer support) ─────────────────────────
  function parseName(r, buf) {
    let name = '';
    let jumped = false;
    let savedPos = -1;
    const maxJumps = 10;
    let jumps = 0;

    while (true) {
      if (r.pos >= buf.length) break;
      const len = buf[r.pos];
      if (len === 0) { r.pos++; break; }
      if ((len & 0xc0) === 0xc0) {
        // Compression pointer.
        if (r.pos + 1 >= buf.length) break;
        const ptr = ((len & 0x3f) << 8) | buf[r.pos + 1];
        r.pos += 2;
        if (!jumped) savedPos = r.pos;
        r.pos = ptr;
        jumped = true;
        if (++jumps > maxJumps) break;
      } else {
        r.pos++;
        const label = buf.slice(r.pos, r.pos + len);
        r.pos += len;
        name += String.fromCharCode(...label) + '.';
      }
    }

    if (jumped && savedPos !== -1) r.pos = savedPos;
    return name || '.';
  }

  // ── Helper string functions ──────────────────────────────────────────────────
  const TYPE_NAMES = {
    1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX', 16:'TXT', 28:'AAAA',
    33:'SRV', 35:'NAPTR', 39:'DNAME', 41:'OPT', 43:'DS', 46:'RRSIG', 47:'NSEC',
    48:'DNSKEY', 50:'NSEC3', 52:'TLSA', 64:'SVCB', 65:'HTTPS', 99:'SPF', 257:'CAA',
    255:'ANY',
  };
  function typeStr(t)  { return TYPE_NAMES[t] ?? `TYPE${t}`; }
  function classStr(c) { return c === 1 ? 'IN' : c === 3 ? 'CH' : c === 255 ? 'ANY' : `CLASS${c}`; }
  function algStr(a)   {
    const m = { 1:'RSAMD5', 3:'DSA', 5:'RSASHA1', 7:'RSASHA1-NSEC3-SHA1', 8:'RSASHA256',
                10:'RSASHA512', 13:'ECDSAP256SHA256', 14:'ECDSAP384SHA384', 15:'ED25519', 16:'ED448' };
    return m[a] ?? `ALG${a}`;
  }
  function digestTypeStr(d) { return { 1:'SHA-1', 2:'SHA-256', 3:'GOST-94', 4:'SHA-384' }[d] ?? `DTYPE${d}`; }
  function optCodeStr(c)    { return { 3:'NSID', 8:'ECS', 10:'COOKIE', 11:'TCP-KEEPALIVE', 12:'PADDING', 19:'ZONEVERSION' }[c] ?? `OPT${c}`; }

  function decodeEdnsOpt(code, data, start, end) {
    const name = optCodeStr(code);
    switch (code) {
      case 3: { // NSID
        const hex = bytesHex(data);
        const txt = Array.from(data).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('');
        return { start, end, field: name, value: data.length ? `${hex} (${txt})` : '(request)' };
      }
      case 8: { // ECS
        if (data.length < 4) break;
        const family  = (data[0] << 8) | data[1];
        const srcPfx  = data[2];
        const scpPfx  = data[3];
        const addrBytes = data.slice(4);
        const familyStr = family === 1 ? 'IPv4' : family === 2 ? 'IPv6' : `AF${family}`;
        const addrHex   = addrBytes.length ? bytesHex(addrBytes) : '0';
        return { start, end, field: name, value: `${familyStr}/${srcPfx} scope=${scpPfx} addr=${addrHex}` };
      }
      case 19: { // ZONEVERSION
        if (data.length < 2) break;
        const labelCount = data[0];
        const zvType     = data[1];
        const version    = data.slice(2);
        const typeName   = zvType === 0 ? 'SOA-SERIAL' : zvType >= 246 ? 'private-use' : `type ${zvType}`;
        let verStr = '';
        if (version.length === 4) {
          const val = ((version[0] << 24) | (version[1] << 16) | (version[2] << 8) | version[3]) >>> 0;
          verStr = zvType === 0 ? ` serial=${val}` : ` value=${val} (0x${bytesHex(version)})`;
        } else if (version.length) {
          verStr = ` version=${bytesHex(version)}`;
        }
        return { start, end, field: name, value: `labels=${labelCount} ${typeName}${verStr}` };
      }
      default: break;
    }
    return { start, end, field: name, value: data.length ? bytesHex(data) : '(empty)' };
  }
  function bytesHex(b)      { return [...b].map(x => x.toString(16).padStart(2,'0')).join(''); }
  function tsStr(epoch) {
    try { return new Date(epoch * 1000).toISOString().replace('T',' ').replace('.000Z',' UTC'); }
    catch { return String(epoch); }
  }
  function decodeBitmap(bytes) {
    const types = [];
    let i = 0;
    while (i < bytes.length) {
      const windowBlock = bytes[i++];
      const bitmapLen   = bytes[i++];
      for (let j = 0; j < bitmapLen; j++) {
        const byte = bytes[i + j];
        for (let bit = 7; bit >= 0; bit--) {
          if (byte & (1 << bit)) {
            types.push(typeStr(windowBlock * 256 + j * 8 + (7 - bit)));
          }
        }
      }
      i += bitmapLen;
    }
    return types.join(' ');
  }

  return { parse };
})();
