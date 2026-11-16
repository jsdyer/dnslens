export const resolvers = {
  google: { name: 'Google Public DNS', endpoint: 'https://dns.google/resolve' },
  cloudflare: { name: 'Cloudflare 1.1.1.1', endpoint: 'https://cloudflare-dns.com/dns-query' },
};

export const rrTypes = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  DS: 43, RRSIG: 46, DNSKEY: 48, HTTPS: 65, CAA: 257,
};

export const statusNames = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
  4: 'NOTIMP', 5: 'REFUSED',
};

export const queryTypes = ['A', 'AAAA', 'CNAME', 'HTTPS', 'NS', 'MX', 'TXT', 'SOA', 'CAA', 'DS', 'DNSKEY'];

function expandIPv6(text) {
  let value = text;
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const suffix = value.slice(lastColon + 1).split('.').map(Number);
    if (suffix.length !== 4) throw new Error('Invalid IPv6 address.');
    value = value.slice(0, lastColon + 1) + [
      (suffix[0] * 256 + suffix[1]).toString(16),
      (suffix[2] * 256 + suffix[3]).toString(16),
    ].join(':');
  }
  const [left, right] = value.split('::');
  const before = left ? left.split(':') : [];
  const after = right ? right.split(':') : [];
  const fill = right === undefined ? [] : Array(8 - before.length - after.length).fill('0');
  return [...before, ...fill, ...after].map(part => part.padStart(4, '0')).join('');
}

export function normalizeInput(raw) {
  const name = raw.trim().replace(/\.$/, '');
  if (!name || name.length > 512 || /[\s/%\\@?#]/u.test(name)) {
    throw new Error('Enter a domain name or public IP address.');
  }
  if (name.includes(':')) {
    const inner = name.replace(/^\[(.*)\]$/, '$1');
    try {
      const hostname = new URL('https://[' + inner + ']/').hostname;
      const canonical = hostname.slice(1, -1);
      const hex = expandIPv6(canonical);
      return {
        kind: 'ipv6',
        value: canonical,
        reverse: [...hex].reverse().join('.') + '.ip6.arpa',
      };
    } catch {
      throw new Error('Enter a valid IPv6 address without a port or zone identifier.');
    }
  }
  if (/^[\d.]+$/.test(name)) {
    const octets = name.split('.');
    if (octets.length !== 4 || !octets.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255)) {
      throw new Error('Enter an IPv4 address in four decimal octets.');
    }
    return { kind: 'ipv4', value: name, reverse: [...octets].reverse().join('.') + '.in-addr.arpa' };
  }
  try {
    const hostname = new URL('https://' + name).hostname.toLowerCase().replace(/\.$/, '');
    const labels = hostname.split('.');
    if (hostname.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1))
        || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new Error('Invalid DNS name.');
    }
    return { kind: 'domain', value: hostname };
  } catch {
    throw new Error('Enter a valid public hostname such as coolcode.ca, without a URL or port.');
  }
}

export function parseTxt(data) {
  const text = data.trim();
  if (!text.startsWith('"')) return text;
  const parts = [...text.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
  return parts.map(match => match[1].replace(/\\(\d{3}|.)/g, (_, fragment) =>
    /^\d{3}$/.test(fragment) ? String.fromCharCode(Number(fragment)) : fragment,
  )).join('');
}

const sameName = (a, b) => typeof a === 'string' && a.replace(/\.$/, '').toLowerCase() === b.replace(/\.$/, '').toLowerCase();

export function answersFor(section) {
  return section?.answers?.filter(answer => answer.type === rrTypes[section.type]) ?? [];
}

function resultFor(section, pattern) {
  const records = answersFor(section).map(answer => parseTxt(answer.data)).filter(value => pattern.test(value));
  if (!section || section.failed || ![0, 3].includes(section.status)) return { level: 'issue', summary: 'Lookup unavailable', records };
  if (records.length > 1) return { level: 'warn', summary: 'Multiple records', records };
  if (records.length === 0) return { level: 'quiet', summary: 'No matching TXT returned', records };
  return { level: 'ok', summary: 'Record published', records };
}

function tagValues(text) {
  return new Map(text.split(';').map(item => item.trim().split(/\s*=\s*(.*)/s).slice(0, 2)).filter(pair => pair.length === 2));
}

export function emailFindings(sections, target) {
  const spf = resultFor(sections.find(item => item.type === 'TXT' && sameName(item.name, target)), /^v=spf1(?:\s|$)/i);
  if (spf.records.length === 1) {
    const modifiers = spf.records[0].split(/\s+/);
    const all = modifiers.find(item => /^[+?~-]?all$/i.test(item));
    const label = { '-all': 'Fail for other senders', '~all': 'Softfail for other senders', '?all': 'Neutral for other senders' }[all?.toLowerCase()];
    if (all && /^\+?all$/i.test(all)) Object.assign(spf, { level: 'warn', summary: 'Permits any sender at the all mechanism' });
    else if (label) spf.summary = label;
  }
  const dmarc = resultFor(sections.find(item => sameName(item.name, '_dmarc.' + target)), /^v=DMARC1(?:\s*;|$)/i);
  if (dmarc.records.length === 1) {
    const policy = tagValues(dmarc.records[0]).get('p');
    if (['none', 'quarantine', 'reject'].includes(policy)) dmarc.summary = 'Published policy: ' + policy;
    else Object.assign(dmarc, { level: 'warn', summary: 'Published record lacks a recognized p= policy' });
  }
  const sts = resultFor(sections.find(item => sameName(item.name, '_mta-sts.' + target)), /^v=STSv1(?:\s*;|$)/);
  if (sts.records.length === 1) {
    if (tagValues(sts.records[0]).get('id')) sts.summary = 'DNS policy ID published';
    else Object.assign(sts, { level: 'warn', summary: 'Published record lacks an id= tag' });
  }
  return { spf, dmarc, sts };
}

export function parseDns(payload, target) {
  if (!payload || !Number.isInteger(payload.Status)) throw new Error('The resolver returned an unreadable response.');
  return {
    ...target,
    status: payload.Status,
    validated: payload.AD === true,
    truncated: payload.TC === true,
    answers: Array.isArray(payload.Answer) ? payload.Answer.filter(answer =>
      answer && typeof answer.name === 'string' && typeof answer.data === 'string'
      && Number.isInteger(answer.type) && Number.isFinite(answer.TTL),
    ) : [],
    comment: typeof payload.Comment === 'string' ? payload.Comment : '',
  };
}

export function ipMatches(address, cidr, kind) {
  const [network, prefix] = cidr.split('/');
  const bits = kind === 'ipv4' ? 32 : 128;
  const from = kind === 'ipv4'
    ? value => value.split('.').reduce((n, p) => (n << 8n) + BigInt(p), 0n)
    : value => BigInt('0x' + expandIPv6(value));
  const length = Number(prefix);
  if (prefix === undefined || !Number.isInteger(length) || length < 0 || length > bits) return false;
  const mask = BigInt(bits - length);
  return from(address) >> mask === from(network) >> mask;
}

export function registryFor(value, services) {
  let best = { length: -1, base: '' };
  if (!Array.isArray(services)) return '';
  for (const entry of services) {
    if (!Array.isArray(entry?.[0]) || !Array.isArray(entry[1])) continue;
    const base = entry[1].find(url => typeof url === 'string' && url.startsWith('https://'));
    if (!base) continue;
    for (const part of entry[0]) {
      if (typeof part !== 'string') continue;
      const length = value.kind === 'domain' ? part.length : Number(part.split('/')[1]);
      const match = value.kind === 'domain'
        ? sameName(value.value, part) || value.value.endsWith('.' + part.toLowerCase())
        : ipMatches(value.value, part, value.kind);
      if (match && length > best.length) best = { length, base };
    }
  }
  return best.base;
}

export function registrationCandidates(target) {
  if (target.kind !== 'domain') return [target.value];
  const parts = target.value.split('.');
  const candidates = parts.slice(0, -1).map((_, index) => parts.slice(index).join('.'));
  return candidates.length <= 6 ? candidates : [...candidates.slice(0, 5), candidates.at(-1)];
}

function recordIdentity(row) {
  const domain = name => name.toLowerCase().replace(/\.$/, '');
  let data = row.data.trim();
  if ([rrTypes.CNAME, rrTypes.NS, rrTypes.PTR].includes(row.type)) {
    data = domain(data);
  } else if (row.type === rrTypes.MX || row.type === rrTypes.SOA) {
    const parts = data.split(/\s+/);
    const names = row.type === rrTypes.MX ? [1] : [0, 1];
    for (const index of names) {
      if (parts[index]) parts[index] = domain(parts[index]);
    }
    data = parts.join(' ');
  } else if (row.type === rrTypes.AAAA) {
    try { data = new URL('https://[' + data + ']/').hostname.slice(1, -1); } catch {}
  }
  return JSON.stringify([domain(row.name), row.type, data]);
}

export function compareRecordSets(first, second) {
  if ([first, second].some(entry => !entry || entry.failed || entry.truncated
    || ![0, 3].includes(entry.status))) return 'unavailable';
  const left = new Set(answersFor(first).map(recordIdentity));
  const right = new Set(answersFor(second).map(recordIdentity));
  if (first.status !== second.status || left.size !== right.size
    || [...left].some(item => !right.has(item))) return 'different';
  return first.validated === second.validated ? 'same' : 'dnssec';
}

export function exportText(report) {
  const lines = ['DNS Lens report', report.target.value, report.observed, report.resolver, ''];
  for (const answer of report.dns) {
    const state = answer.failed || statusNames[answer.status] || String(answer.status);
    lines.push(answer.type + ' ' + answer.name + ' — ' + state);
    for (const row of answer.answers) {
      const type = Object.keys(rrTypes).find(key => rrTypes[key] === row.type) ?? row.type;
      lines.push([row.name, row.TTL, type, row.data].join('\t'));
    }
    lines.push('');
  }
  if (report.comparison) {
    lines.push('Resolver comparison — ' + report.comparison.resolver);
    report.comparison.dns.forEach((entry, index) => {
      lines.push(entry.type + ' ' + entry.name + ' — ' + compareRecordSets(report.dns[index], entry));
      for (const row of entry.answers) lines.push([row.name, row.TTL, row.type, row.data].join('\t'));
    });
    lines.push('');
  }
  if (report.email) {
    for (const [name, finding] of Object.entries(report.email)) lines.push(name.toUpperCase() + ' — ' + finding.summary);
  }
  if (report.rdap) {
    lines.push('', 'RDAP — ' + report.rdap.summary);
    if (report.rdap.source) lines.push(report.rdap.source);
    for (const row of report.rdap.fields ?? []) lines.push(row.join(': '));
  }
  return lines.join('\n');
}
