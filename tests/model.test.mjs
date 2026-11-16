import test from 'node:test';
import assert from 'node:assert/strict';
import {
  answersFor, compareRecordSets, dkimName, dkimSelectors, emailFindings, exportText, ipMatches, normalizeInput, parseDns, parseTxt, registrationCandidates, registryFor,
} from '../web/model.mjs';

test('canonicalizes IDN and produces IPv4 and IPv6 reverse lookup names', () => {
  assert.deepEqual(normalizeInput('Café.ca.'), { kind: 'domain', value: 'xn--caf-dma.ca' });
  assert.deepEqual(normalizeInput('8.8.4.4'), { kind: 'ipv4', value: '8.8.4.4', reverse: '4.4.8.8.in-addr.arpa' });
  const v6 = normalizeInput('[2001:0DB8::1]');
  assert.equal(v6.value, '2001:db8::1');
  assert.match(v6.reverse, /^1(?:\.0){23}\.8\.b\.d\.0\.1\.0\.0\.2\.ip6\.arpa$/);
  assert.equal(normalizeInput('::ffff:8.8.4.4').reverse.split('.').length, 34);
  for (const value of ['08.8.8.8', 'https://coolcode.ca/', '256.1.1.1', 'bad!.ca', '2606::fff::1']) {
    assert.throws(() => normalizeInput(value));
  }
});

test('handles escaped TXT segments and reports scoped mail signals', () => {
  assert.equal(parseTxt('"v=spf1 " "-all"'), 'v=spf1 -all');
  assert.equal(parseTxt('"ab\\034c"'), 'ab"c');
  const dns = (name, values, response = 0) => parseDns({
    Status: response, Answer: values.map(data => ({ name, type: 16, TTL: 3600, data })),
  }, { name, type: 'TXT' });
  const sections = [
    dns('coolcode.ca', ['v=spf1 +all']),
    dns('_DMARC.COOLCODE.CA.', ['v=DMARC1; p=reject;']),
    dns('_mta-sts.coolcode.ca', [], 2),
  ];
  const findings = emailFindings(sections, 'coolcode.ca');
  assert.equal(findings.spf.level, 'warn');
  assert.equal(findings.dmarc.summary, 'Published policy: reject');
  assert.equal(findings.sts.level, 'issue');
});

test('matches the longest registry prefix and treats a TLD as a whole DNS label', () => {
  assert.equal(ipMatches('2606:4700:4700::1111', '2600::/12', 'ipv6'), true);
  assert.equal(ipMatches('2001:db8::1', '2600::/12', 'ipv6'), false);
  assert.equal(ipMatches('138.197.0.1', '138.0.0.0/8', 'ipv4'), true);
  assert.equal(registryFor(normalizeInput('138.197.0.1'), [
    [['138.0.0.0/8'], ['https://one.example/']],
    [['138.197.0.0/16'], ['https://two.example/']],
  ]), 'https://two.example/');
  assert.equal(registryFor(normalizeInput('coolcode.ca'), [[['ca'], ['https://example.com/']]]), 'https://example.com/');
  assert.equal(registryFor(normalizeInput('coolcode.cat'), [[['ca'], ['https://example.com/']]]), '');
  assert.deepEqual(registrationCandidates(normalizeInput('www.example.co.uk')), ['www.example.co.uk', 'example.co.uk', 'co.uk']);
});

test('preserves DNS failure responses and counts only the requested answer type', () => {
  const data = parseDns({ Status: 0, AD: true, Answer: [
    { name: 'www.example.ca', type: 5, data: 'example.ca.', TTL: 300 },
    { name: 'example.ca', type: 1, data: '203.0.113.5', TTL: 300 },
  ] }, { name: 'www.example.ca', type: 'A' });
  assert.equal(data.validated, true);
  assert.equal(answersFor(data).length, 1);
  assert.equal(data.answers.length, 2);
  assert.equal(parseDns({ Status: 2 }, { name: 'example.ca', type: 'MX' }).status, 2);
  assert.throws(() => parseDns({}, {}));
});

test('resolver comparisons ignore order and TTL, but expose answer, status and AD differences', () => {
  const make = (targets, options = {}) => ({
    name: 'example.ca', type: 'MX', status: 0, validated: true, ...options,
    answers: targets.map(([data, TTL]) => ({ name: 'Example.CA.', type: 15, data, TTL })),
  });
  const google = make([['10 MX.Example.CA.', 100], ['20 backup.example.ca.', 100]]);
  const cloudflare = make([['20 backup.example.ca', 25], ['10 mx.example.ca', 25]]);
  assert.equal(compareRecordSets(google, cloudflare), 'same');
  assert.equal(compareRecordSets(google, { ...cloudflare, validated: false }), 'dnssec');
  assert.equal(compareRecordSets(google, make([['20 backup.example.ca', 25]])), 'different');
  assert.equal(compareRecordSets(make([]), make([], { status: 3 })), 'different');
  for (const unavailable of [{ status: 2 }, { truncated: true }, { failed: 'Timeout' }]) {
    assert.equal(compareRecordSets(google, { ...cloudflare, ...unavailable }), 'unavailable');
  }
});

test('normalizes and bounds exact DKIM selector queries', () => {
  const target = normalizeInput('Café.ca');
  const selectors = dkimSelectors(' Selector1, MAIL.2026 selector1 ', target);
  assert.deepEqual(selectors, ['selector1', 'mail.2026']);
  assert.equal(dkimName(selectors[0], target.value), 'selector1._domainkey.xn--caf-dma.ca');
  for (const invalid of ['a.,', 'a/b', 'a@b', '_key', '-x', 'a..b', 'a b c d', 'a'.repeat(64)]) {
    assert.throws(() => dkimSelectors(invalid, target));
  }
  assert.deepEqual(dkimSelectors('', normalizeInput('8.8.8.8')), []);
  assert.throws(() => dkimSelectors('a', normalizeInput('8.8.8.8')), /domain name/);
});

test('scoped mail policies distinguish published keys, revoked keys, delegation, and failed queries', () => {
  const domain = 'example.ca';
  const key = (selector, text, options = {}) => {
    const name = dkimName(selector, domain);
    return parseDns({
      Status: 0, ...options,
      Answer: [
        { name, type: 5, TTL: 200, data: 'customer.keys.example.net.' },
        ...(text === undefined ? [] : [{ name: 'customer.keys.example.net.', type: 16, TTL: 200, data: text }]),
      ],
    }, { name, type: 'TXT' });
  };
  const tls = (data, extra = {}) => parseDns({
    Status: 0, ...extra, Answer: [{ name: '_smtp._tls.example.ca.', type: 16, TTL: 90, data }],
  }, { name: '_smtp._tls.example.ca', type: 'TXT' });

  const selectors = ['current', 'retired', 'bad', 'duplicate', 'failed', 'missing', 'newkey'];
  const lookups = [
    key('current', '"v=DKIM1; p=QUJD" "RA=="'),
    key('retired', 'v=DKIM1; k=rsa; p='),
    key('bad', 'v=DKIM1; p=hey!'),
    key('duplicate', 'v=DKIM1; p=QUJD; p=QUJD'),
    key('failed', 'v=DKIM1; p=QUJD', { TC: true }),
    key('missing', undefined, { Status: 3 }),
    key('newkey', 'k=ed25519; p=QUJD'),
    tls('v=TLSRPTv1; rua=mailto:tls@example.net, https://reports.example.net/intake'),
  ];
  const report = emailFindings(lookups, domain, selectors);
  assert.equal(report.tlsRpt.summary, '2 report destinations published');
  assert.deepEqual(report.dkim.map(finding => [finding.level, finding.summary]), [
    ['ok', 'RSA key record published'],
    ['warn', 'Revoked key (empty p=)'],
    ['warn', 'Public-key text is not valid Base64'],
    ['warn', 'Repeated tags in the key record'],
    ['issue', 'Lookup unavailable'],
    ['quiet', 'No matching TXT returned'],
    ['ok', 'Ed25519 key record published'],
  ]);
  assert.deepEqual(report.dkim[0].aliases, ['customer.keys.example.net.']);
  assert.equal(emailFindings([tls('v=TLSRPTv1; rua=https:maybe')], domain).tlsRpt.level, 'warn');
  assert.equal(emailFindings([tls('v=TLSRPTv1; rua=mailto:tls@example.net', { Status: 2 })], domain).tlsRpt.level, 'issue');
  const exported = exportText({ target: { value: domain }, observed: 'test', resolver: 'test', dns: lookups, email: report });
  assert.match(exported, /DKIM retired — Revoked key/);
  assert.match(exported, /TLS-RPT — 2 report destinations published/);
});
