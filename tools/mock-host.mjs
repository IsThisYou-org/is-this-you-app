import http from 'node:http';

const zones = new Map();
const port = Number(process.env.PORT || 8080);
const ahead = Number(process.env.SERIAL_FUTURE_SECONDS || 300);
const behind = Number(process.env.SERIAL_PAST_SECONDS || 3600);
const expectedNs = (process.env.SERVICE_NS || 'ns1.example.net.,ns2.example.net.')
  .split(',')
  .map(name => name.trim().toLowerCase())
  .filter(Boolean)
  .sort();

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(json);
}

const server = http.createServer((req, res) => {
  if (!req.url || !req.url.startsWith('/v1/zones/')) {
    send(res, 404, { error: 'not_found', message: 'not found' });
    return;
  }
  if (req.method !== 'POST') {
    send(res, 404, { error: 'not_found', message: 'not found' });
    return;
  }
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      send(res, 400, { error: 'bad_request', message: 'body is not JSON' });
      return;
    }
    if (body.kind !== 'dnsauth#signedZone') {
      send(res, 400, { error: 'bad_request', message: 'kind must be "dnsauth#signedZone"' });
      return;
    }
    const soa = (body.rrsets || []).find(rr => rr.type === 'SOA');
    const serial = Number((soa?.rrdatas?.[0] || '').trim().split(/\s+/)[2]);
    const now = Number(process.env.MOCK_NOW || Math.floor(Date.now() / 1000));
    if (serial > now + ahead) {
      send(res, 422, { error: 'serial_in_future', message: 'SOA serial is too far ahead of the service clock' });
      return;
    }
    if (serial < now - behind) {
      send(res, 422, { error: 'serial_stale', message: 'SOA serial is outside the freshness window' });
      return;
    }
    const previous = zones.get(body.apex);
    if (previous != null && serial <= previous) {
      send(res, 422, {
        error: 'serial_not_increased',
        message: `SOA serial ${serial} is not greater than the stored serial ${previous}`,
      });
      return;
    }
    const ns = (body.rrsets || []).find(rr => rr.type === 'NS');
    const got = (ns?.rrdatas || []).map(item => item.trim().toLowerCase()).sort();
    if (got.join(',') !== expectedNs.join(',')) {
      send(res, 422, { error: 'ns_set_mismatch', message: 'parent delegation NS set does not equal the apex NS set' });
      return;
    }
    zones.set(body.apex, serial);
    send(res, previous == null ? 201 : 200, {
      apex: body.apex,
      serial,
      catalogUpdated: true,
      nextExpireHint: null,
    });
  });
});

server.listen(port, () => {
  console.log(`mock host on http://127.0.0.1:${port}`);
});
