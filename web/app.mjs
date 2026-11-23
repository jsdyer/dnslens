import { readMigrated } from './storage.mjs';
import {
  answersFor, compareRecordSets, lookupTargets, snapshotChanges, dkimSelectors, emailFindings, exportText, normalizeInput, parseDns, 
  registrationCandidates, registryFor, resolvers, rrTypes, statusNames,
} from './model.mjs?v=workbench';

const get = id => document.getElementById(id);
let active;
let report;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function link(label, href) {
  const node = element('a', label);
  node.href = href;
  node.target = '_blank';
  node.rel = 'noopener noreferrer';
  return node;
}

function status(message, level = '') {
  const output = get('state');
  output.textContent = message;
  output.dataset.level = level;
}

function badge(text, level) {
  const node = element('span', text, 'badge');
  node.dataset.level = level;
  return node;
}

function request(url, signal, accept, ms = 9000, init = {}) {
  return fetch(url, {
    ...init,
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.any([signal, AbortSignal.timeout(ms)]),
    headers: { Accept: accept },
  });
}

function reachability(error) {
  if (error.name === 'TimeoutError') return 'Request timed out.';
  if (error instanceof TypeError) return 'No readable response from this browser.';
  return error.message;
}

async function queryDNS(target, resolver, signal) {
  const url = new URL(resolver.endpoint);
  url.search = new URLSearchParams({ name: target.name, type: String(rrTypes[target.type] ?? target.type), do: '1' });
  const started = performance.now();
  const elapsed = () => Math.round(performance.now() - started);
  try {
    const response = await request(url, signal, 'application/dns-json');
    if (!response.ok) throw new Error('Resolver HTTP ' + response.status + '.');
    const payload = await response.json();
    return parseDns(payload, { ...target, source: url.href, elapsed: elapsed() });
  } catch (error) {
    return { ...target, source: url.href, elapsed: elapsed(), failed: reachability(error), answers: [] };
  }
}

function dnsState(entry) {
  if (entry.failed) return ['Request failed', 'issue'];
  if (entry.truncated) return ['Truncated reply', 'warn'];
  if (entry.status === 3) return ['NXDOMAIN', 'quiet'];
  if (entry.status !== 0) return [statusNames[entry.status] ?? ('DNS status ' + entry.status), 'issue'];
  const count = answersFor(entry).length;
  if (!count) return ['No ' + entry.type + ' record', 'quiet'];
  return [count + ' ' + entry.type + (count === 1 ? ' record' : ' records'), 'ok'];
}

function renderLedger(data) {
  const received = data.dns.filter(item => !item.failed);
  const answered = data.dns.filter(item => answersFor(item).length > 0 && item.status === 0);
  const validated = received.filter(item => item.validated).length;
  const failures = data.dns.length - received.length + received.filter(item => ![0, 3].includes(item.status)).length;
  const cards = [
    ['Lookups with records', answered.length + ' / ' + data.dns.length],
    ['DNSSEC authenticated data', validated ? validated + ' replies with AD set' : 'No AD signal returned'],
    ['Failed lookups', String(failures)],
  ];
  const container = get('summary');
  container.replaceChildren(...cards.map(([title, value]) => {
    const card = element('article');
    card.append(element('h3', title), element('p', value));
    return card;
  }));
  return { answered, failures };
}

async function copy(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    status(message);
  } catch {
    status('Clipboard access was unavailable. Select text in the report or download JSON.', 'issue');
  }
}

function renderRecords(data) {
  const all = data.dns.map(entry => {
    const item = element('details');
    const [stateText, stateLevel] = dnsState(entry);
    const title = element('summary', entry.type + (entry.name === data.target.value ? '' : ' · ' + entry.name));
    title.append(badge(stateText, stateLevel));
    const body = element('div', undefined, 'dns-body');
    body.append(element('p', entry.failed || (entry.validated ? 'Resolver set the DNSSEC AD bit.' : 'Resolver did not set the DNSSEC AD bit.'), 'muted'));
    body.append(element('p', 'HTTPS request: ' + entry.elapsed + ' ms', 'muted'));
    if (entry.comment) body.append(element('p', entry.comment, 'muted'));
    for (const row of entry.answers) {
      const itemRow = element('div', undefined, 'rr');
      const display = element('div');
      const label = Object.keys(rrTypes).find(type => rrTypes[type] === row.type) ?? ('TYPE' + row.type);
      display.append(element('div', label + ' · ' + row.name + ' · TTL ' + row.TTL + 's', 'muted'), element('code', row.data));
      const btn = element('button', 'Copy', 'copy-record');
      btn.type = 'button';
      btn.setAttribute('aria-label', 'Copy ' + label + ' record for ' + row.name);
      btn.addEventListener('click', () => copy(row.data, label + ' record copied.'));
      itemRow.append(display, btn);
      body.append(itemRow);
    }
    body.append(link('Resolver response ↗', entry.source));
    item.open = entry.status === 0 && ['A', 'AAAA', 'PTR', 'MX'].includes(entry.type) && answersFor(entry).length > 0;
    item.append(title, body);
    return item;
  });
  get('records').replaceChildren(...all);
}

function renderComparison(data) {
  get('divergence').hidden = !data?.comparison;
  if (!data?.comparison) return;
  const pairs = data.dns.map((first, index) => {
    const second = data.comparison.dns[index];
    return { first, second, outcome: compareRecordSets(first, second) };
  });
  const summary = new Map();
  for (const { outcome } of pairs) summary.set(outcome, (summary.get(outcome) ?? 0) + 1);
  get('divergence-summary').textContent = [
    (summary.get('same') ?? 0) + ' matching',
    (summary.get('different') ?? 0) + ' answer differences',
    (summary.get('dnssec') ?? 0) + ' DNSSEC flag differences',
    (summary.get('unavailable') ?? 0) + ' unavailable',
  ].join(' · ');
  const labels = {
    same: ['Same record set', 'ok'],
    different: ['Different result', 'warn'],
    dnssec: ['DNSSEC flags differ', 'warn'],
    unavailable: ['Comparison unavailable', 'issue'],
  };
  const rows = pairs.filter(({ outcome }) => outcome !== 'same' || !get('differences-only').checked);
  get('comparison-pairs').replaceChildren(...rows.map(({ first, second, outcome }) => {
    const detail = element('details');
    detail.open = outcome === 'different' || outcome === 'dnssec';
    const title = element('summary', first.type + (first.name === data.target.value ? '' : ' · ' + first.name));
    title.append(badge(...labels[outcome]));
    const columns = element('div', undefined, 'resolver-pair');
    for (const [name, entry] of [[data.resolver, first], [data.comparison.resolver, second]]) {
      const column = element('div', undefined, 'resolver-column');
      const [state] = dnsState(entry);
      column.append(element('h3', name), element('p', state + ' · AD ' + (entry.failed ? 'unavailable' : entry.validated ? 'set' : 'clear'), 'muted'));
      if (entry.failed) column.append(element('p', entry.failed, 'muted'));
      for (const row of answersFor(entry)) {
        const block = element('div', undefined, 'comparison-record');
        block.append(element('span', row.name + ' · TTL ' + row.TTL + 's', 'muted'), element('code', row.data));
        column.append(block);
      }
      column.append(link('Resolver response ↗', entry.source));
      columns.append(column);
    }
    detail.append(title, columns);
    return detail;
  }));
  if (!rows.length) get('comparison-pairs').append(element('p', 'All compared replies match.', 'muted divergence-note'));
}

function renderEmail(data, signal) {
  get('email-panel').hidden = !data.email;
  if (!data.email) return;
  const fields = [
    ['SPF', data.email.spf, 'https://www.rfc-editor.org/rfc/rfc7208.html'],
    ['DMARC', data.email.dmarc, 'https://www.rfc-editor.org/rfc/rfc9989.html'],
    ['MTA-STS', data.email.sts, 'https://www.rfc-editor.org/rfc/rfc8461.html'],
    ['TLS-RPT', data.email.tlsRpt, 'https://www.rfc-editor.org/rfc/rfc8460.html'],
    ...data.email.dkim.map(finding => ['DKIM · ' + finding.selector, finding, 'https://www.rfc-editor.org/rfc/rfc6376.html']),
  ];
  get('email').replaceChildren(...fields.map(([title, finding, href]) => {
    const card = element('div', undefined, 'find');
    const h3 = element('h3', title);
    const outcome = badge(finding.summary, finding.level);
    card.append(h3, outcome);
    for (const alias of finding.aliases ?? []) card.append(element('p', 'CNAME → ' + alias, 'muted'));
    for (const text of finding.records) card.append(element('code', text));
    const controls = element('div', undefined, 'action-row');
    controls.append(link((finding.selector ? 'DKIM' : title) + ' standard ↗', href));
    if (title === 'MTA-STS' && finding.records.length) {
      const uri = new URL('https://mta-sts.' + data.target.value + '/.well-known/mta-sts.txt').href;
      const action = element('button', 'Fetch HTTPS policy');
      action.type = 'button';
      const output = element('div', undefined, 'muted');
      output.setAttribute('role', 'status');
      controls.append(action, link('Open policy ↗', uri));
      card.append(controls, output);
      action.addEventListener('click', async () => {
        action.disabled = true;
        output.textContent = 'Fetching the policy host…';
        try {
          const response = await request(uri, signal, 'text/plain', 7500, { redirect: 'error' });
          if (!response.ok) throw new Error('Policy host HTTP ' + response.status + '.');
          if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'text/plain') {
            throw new Error('Policy response has an unexpected content type.');
          }
          if (!response.body) throw new Error('Policy response has no readable body.');
          const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
          let text = '';
          for (;;) {
            const result = await reader.read();
            if (result.done) break;
            text += result.value;
            if (text.length > 65536) {
              await reader.cancel();
              throw new Error('Policy response exceeds the 64 KiB limit.');
            }
          }
          if (signal.aborted) return;
          data.email.sts.policy = { source: uri, checked: new Date().toISOString(), text };
          output.replaceChildren('Policy text retrieved. Below is the host response.', element('pre', text));
        } catch (error) {
          if (!signal.aborted) output.textContent = reachability(error) + ' HTTPS policy hosts may block this browser. Try the direct link.';
        } finally {
          action.disabled = false;
        }
      });
      return card;
    }
    card.append(controls);
    return card;
  }));
}

function registrationFields(target, payload) {
  const fields = [
    ['Object', payload.ldhName ?? payload.name],
    ['Handle', payload.handle],
    ['Status', Array.isArray(payload.status) ? payload.status.join(', ') : ''],
  ];
  if (target.kind === 'domain') {
    const registrar = payload.entities?.find(person => Array.isArray(person?.roles) && person.roles.includes('registrar'));
    const name = registrar?.vcardArray?.[1]?.find?.(entry => entry?.[0] === 'fn')?.[3];
    fields.push(['Registrar', name ?? registrar?.handle]);
    if (Array.isArray(payload.nameservers)) {
      fields.push(['Nameservers', payload.nameservers.map(entry => entry?.ldhName).filter(Boolean).slice(0, 20).join(', ')]);
    }
    for (const [event, label] of [['registration', 'Registered'], ['expiration', 'Expires'], ['last changed', 'Updated']]) {
      const date = payload.events?.find?.(entry => entry.eventAction === event)?.eventDate;
      if (date) fields.push([label, date]);
    }
  } else {
    fields.push(['First address', payload.startAddress], ['Last address', payload.endAddress], ['Country code', payload.country]);
  }
  return fields.filter(pair => typeof pair[1] === 'string' && pair[1].length > 0);
}

async function queryRegistration(target, signal) {
  const bootstrapName = target.kind === 'domain' ? 'dns' : target.kind;
  const bootstrap = 'https://data.iana.org/rdap/' + bootstrapName + '.json';
  let source = bootstrap;
  try {
    const list = await request(bootstrap, signal, 'application/json', 7500);
    if (!list.ok) throw new Error('IANA bootstrap HTTP ' + list.status + '.');
    const base = registryFor(target, (await list.json()).services);
    if (!base) return { summary: 'IANA returned no HTTPS RDAP endpoint for this lookup.', source, bootstrap, fields: [] };
    const candidates = registrationCandidates(target);
    for (const candidate of candidates) {
      source = new URL((target.kind === 'domain' ? 'domain/' : 'ip/') + encodeURIComponent(candidate), base.replace(/\/?$/, '/')).href;
      const answer = await request(source, signal, 'application/rdap+json,application/json', 6500);
      if (answer.status === 404) continue;
      if (!answer.ok) throw new Error('Registry HTTP ' + answer.status + '.');
      const payload = await answer.json();
      if (!payload?.objectClassName) throw new Error('The registry returned an unreadable RDAP object.');
      const summary = candidate === target.value ? 'Registry response received.' : 'Registry record for parent name ' + candidate + '.';
      return { summary, source, bootstrap, fields: registrationFields(target, payload) };
    }
    return { summary: 'Registry returned no record for the tested names or address.', source, bootstrap, fields: [] };
  } catch (error) {
    return { summary: reachability(error), source, bootstrap, fields: [], failed: true };
  }
}

function renderRDAP(data) {
  const node = get('rdap');
  node.replaceChildren(element('p', data?.summary ?? 'Finding the registry through IANA…', 'muted'));
  if (!data) return;
  if (data.fields.length) {
    const fields = element('dl');
    for (const [title, value] of data.fields) {
      const row = element('div');
      row.append(element('dt', title), element('dd', value));
      fields.append(row);
    }
    node.append(fields);
  }
  if (data.source) node.append(link('Registration source ↗', data.source));
}

async function runLookup(input) {
  const mode = get('mode').value;
  let target;
  try {
    target = normalizeInput(input, mode === 'record');
  } catch (error) {
    status(error.message, 'issue');
    get('host').focus();
    return;
  }
  let selectors;
  try {
    selectors = ['full','mail'].includes(mode) ? dkimSelectors(get('dkim-selectors').value, target) : [];
  } catch (error) {
    status(error.message, 'issue');
    get('dkim-selectors').focus();
    return;
  }
  active?.abort();
  const run = new AbortController();
  active = run;
  const signal = run.signal;
  const provider = get('resolver').value;
  const compare = provider === 'both';
  const resolver = resolvers[provider] ?? resolvers.google;
  const source = compare ? 'Google Public DNS and Cloudflare' : resolver.name;
  status('Querying ' + source + ' for ' + target.value + '…');
  get('result').hidden = true;
  report = null;
  const observed = new Date().toISOString();
  const includeRegistration = mode === 'full' || mode === 'delegation' || (target.kind !== 'domain' && mode !== 'record');
  const registration = includeRegistration ? queryRegistration(target,signal) : null;
  const targets = lookupTargets(target,mode,get('record-type').value,selectors);
  get('registration-panel').hidden = !includeRegistration;
  get('baseline').value = '';
  get('diff-state').textContent = '';
  get('diff-rows').replaceChildren();
  const resolveAll = server => Promise.all(targets.map(query => queryDNS(query, server, signal)));
  const [dns, other] = await Promise.all([resolveAll(resolver), compare ? resolveAll(resolvers.cloudflare) : []]);
  if (signal.aborted) return;
  report = { target, observed, resolver: resolver.name, dns };
  if (compare) report.comparison = { resolver: resolvers.cloudflare.name, dns: other };
  if (target.kind === 'domain' && ['mail','full'].includes(mode)) report.email = emailFindings(dns, target.value, selectors);
  get('report-title').textContent = target.value;
  get('provenance').textContent = source + ' · ' + new Date(observed).toLocaleString() + ' · ' + observed;
  const { answered, failures } = renderLedger(report);
  renderRecords(report);
  renderComparison(report);
  renderEmail(report, signal);
  renderRDAP();
  get('result').hidden = false;
  status((
    compare ? 'Resolver comparison complete. '
      : failures ? failures + ' of ' + dns.length + ' DNS lookups failed. '
      : answered.length ? 'DNS lookups complete. ' : 'No requested DNS records were returned. '
  ) + (includeRegistration ? 'Registration lookup runs separately.' : ''));
  if (!includeRegistration) return;
  const current = await registration;
  if (signal.aborted) return;
  report.rdap = current;
  renderRDAP(current);
  if (get('state').textContent.endsWith('Registration lookup runs separately.')) {
    status(get('state').textContent.replace('Registration lookup runs separately.', 'Registration lookup finished.'));
  }
}

get('lookup').addEventListener('submit', event => {
  event.preventDefault();
  runLookup(get('host').value);
});

for (const control of document.querySelectorAll('[data-example]')) {
  control.addEventListener('click', () => {
    get('mode').value = control.dataset.selectors ? 'mail' : 'full';
    showInputs();
    get('host').value = control.dataset.example;
    get('dkim-selectors').value = control.dataset.selectors ?? '';
    get('lookup').requestSubmit();
  });
}

get('differences-only').addEventListener('change', () => renderComparison(report));

get('copy').addEventListener('click', () => {
  if (report) copy(exportText(report), 'Report copied as plain text.');
});

get('export').addEventListener('click', () => {
  if (!report) return;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const objectURL = URL.createObjectURL(blob);
  const file = element('a');
  file.href = objectURL;
  file.download = 'dns-lens-' + report.target.value.replace(/[^a-z0-9.-]/g, '_') + '.json';
  file.click();
  setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
});

function setTheme(dark) {
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  get('theme').textContent = dark ? 'Light mode' : 'Dark mode';
  get('theme').setAttribute('aria-pressed', String(dark));
}
let preferred = null;
try { preferred = readMigrated(localStorage, 'coolcode:dnslens:theme', 'coolcode-dnslens-theme'); } catch {}
setTheme(preferred === 'dark' || (preferred === null && matchMedia('(prefers-color-scheme: dark)').matches));
get('theme').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  setTheme(dark);
  try { localStorage.setItem('coolcode:dnslens:theme', dark ? 'dark' : 'light'); } catch {}
});

for (const type of Object.keys(rrTypes)) get('record-type').append(new Option(type,type));
function showInputs() {
  const mode = get('mode').value;
  get('record-choice').hidden = mode !== 'record';
  get('selector-box').hidden = !['full','mail'].includes(mode);
}
get('mode').addEventListener('change',showInputs);
showInputs();
get('baseline').addEventListener('change', async () => {
  const file = get('baseline').files[0];
  const current = report;
  const output = get('diff-state'), list = get('diff-rows');
  list.replaceChildren();
  output.textContent = '';
  if (!file || !current) return;
  try {
    if (file.size > 2000000) throw new Error('Choose a DNS Lens report smaller than 2 MB.');
    const prior = JSON.parse(await file.text());
    if (current !== report || file !== get('baseline').files[0]) return;
    const rows = snapshotChanges(prior,current);
    const changed = rows.filter(r=>r.state === 'Changed').length;
    const same = rows.filter(r=>r.state === 'Unchanged').length;
    output.textContent = prior.observed+' → '+current.observed+' · '+current.resolver+' · '+changed+' changed, '+same+' unchanged, '+(rows.length-same-changed)+' unavailable or queried only once. TTL countdown and record order are ignored.';
    for (const row of rows.filter(row=>row.state !== 'Unchanged')) {
      const block = element('section',undefined,'find');
      block.append(element('h3',row.name+' · '+row.state));
      for (const text of row.notes??[]) block.append(element('p',text));
      for (const text of row.removed??[]) block.append(element('code','Removed · '+text));
      for (const text of row.added??[]) block.append(element('code','Added · '+text));
      list.append(block);
    }
  } catch (error) {
    if (current === report && file === get('baseline').files[0]) output.textContent = error instanceof SyntaxError ? 'Choose a valid DNS Lens JSON file.' : error.message;
  }
});
