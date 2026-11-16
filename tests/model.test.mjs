import test from 'node:test';
import assert from 'node:assert/strict';
import {
  answersFor, emailFindings, ipMatches, normalizeInput, parseDns, parseTxt, registrationCandidates, registryFor,
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
