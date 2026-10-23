import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { once } from 'node:events';
import net from 'node:net';
import test from 'node:test';

import dnsPacket from 'dns-packet';
import { queryDirectlyUDP, ROOT_SERVER_BOOTSTRAP_IP } from 'dns-self-resolver';

import { getARecord, getResourceRecord, getZoneApex } from '../dnssec-validator.js';

const LOCALHOST = '127.0.0.1';
const TEST_TIMEOUT_MS = 5000;

async function startDnsServer(t, respond) {
    const udp = dgram.createSocket('udp4');
    const connections = new Set();
    const queries = [];
    const errors = [];
    let udpBound = false;
    const tcp = net.createServer(socket => {
        connections.add(socket);
        socket.on('close', () => connections.delete(socket));
        socket.on('error', error => errors.push(error));
        let buffered = Buffer.alloc(0);
        socket.on('data', chunk => {
            buffered = Buffer.concat([buffered, chunk]);
            while (buffered.length >= 2) {
                const length = buffered.readUInt16BE(0);
                if (buffered.length < length + 2) break;
                const response = handleQuery(buffered.subarray(2, length + 2), 'tcp');
                buffered = buffered.subarray(length + 2);
                if (response) {
                    const header = Buffer.alloc(2);
                    header.writeUInt16BE(response.length);
                    socket.write(Buffer.concat([header, response]));
                }
            }
        });
    });

    function handleQuery(message, transport) {
        const query = dnsPacket.decode(message);
        queries.push({ ...query, transport });
        const response = respond(query, transport);
        if (response === null) return null;
        return dnsPacket.encode({
            type: 'response',
            id: query.id,
            questions: query.questions,
            ...response
        });
    }

    udp.on('message', (message, remote) => {
        const response = handleQuery(message, 'udp');
        if (response) udp.send(response, remote.port, remote.address);
    });
    udp.on('error', error => errors.push(error));
    tcp.on('error', error => errors.push(error));
    t.after(async () => {
        for (const socket of connections) socket.destroy();
        const closing = [];
        if (tcp.listening) closing.push(new Promise(resolve => tcp.close(resolve)));
        if (udpBound) closing.push(new Promise(resolve => udp.close(resolve)));
        await Promise.all(closing);
        assert.deepEqual(errors, [], 'DNS test server errors');
    });
    const udpReady = once(udp, 'listening');
    udp.bind(0, LOCALHOST);
    await udpReady;
    udpBound = true;
    const tcpReady = once(tcp, 'listening');
    tcp.listen(0, LOCALHOST);
    await tcpReady;

    return {
        queries,
        query: (domain, serverIp, cache, type, options = {}) => {
            assert.equal(serverIp, LOCALHOST);
            const normalizedOptions = typeof options === 'boolean' ? { useEdns: options } : options;
            return queryDirectlyUDP(domain, LOCALHOST, cache, type, {
                timeoutMs: 1000,
                ...normalizedOptions,
                udpPort: udp.address().port,
                tcpPort: tcp.address().port
            });
        }
    };
}

function assertDnssecQuery(query, type) {
    assert.equal(query.questions[0].type, type);
    assert.equal(query.questions[0].class, 'IN');
    const opt = query.additionals.find(record => record.type === 'OPT');
    assert.ok(opt, 'EDNS OPT record is sent');
    assert.equal(opt.flags & dnsPacket.DNSSEC_OK, dnsPacket.DNSSEC_OK);
    assert.equal(opt.udpPayloadSize, 1232);
}

function dnskeyResponse(query) {
    const name = query.questions[0].name;
    return {
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        answers: [
            { name, type: 'DNSKEY', ttl: 60, data: { flags: 257, algorithm: 18, key: Buffer.alloc(1312, 1) } },
            {
                name, type: 'RRSIG', ttl: 60,
                data: {
                    typeCovered: 'DNSKEY', algorithm: 18, labels: 2, originalTTL: 60,
                    expiration: 2000000000, inception: 1700000000, keyTag: 1234,
                    signersName: 'example.test', signature: Buffer.alloc(2420, 2)
                }
            }
        ]
    };
}

test('実リゾルバーでDO付きUDP問い合わせを送り、DSと不在証明の応答形式を確認する', { timeout: TEST_TIMEOUT_MS }, async t => {
    const ds = { keyTag: 1234, algorithm: 15, digestType: 2, digest: Buffer.alloc(32, 3) };
    const nsec3 = {
        algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from('a1b2', 'hex'),
        nextDomain: Buffer.alloc(20, 4), rrtypes: ['NS', 'SOA', 'RRSIG', 'DNSKEY']
    };
    const server = await startDnsServer(t, query => ({
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        answers: [{ name: query.questions[0].name, type: 'DS', ttl: 60, data: ds }],
        authorities: [{
            name: `${'0'.repeat(32)}.example.test`, type: 'NSEC3', ttl: 60, data: nsec3
        }]
    }));
    const result = await getResourceRecord('example.test', LOCALHOST, 'DS', {
        queryDirectlyUDP: server.query, dnsResponseCache: new Map()
    });
    assert.equal(result.rcode, 'NOERROR');
    assert.deepEqual(result.resourceRecords[0].data, ds);
    assert.deepEqual(result.denialRecords[0].data, nsec3);
    assert.deepEqual(result.rrsigRecords, []);
    assert.deepEqual(result.denialRrsigRecords, []);
    assert.equal(server.queries.length, 1);
    assertDnssecQuery(server.queries[0], 'DS');
});

test('実リゾルバーはTC付きUDP応答からTCPへ切り替え、大きなDNSKEYとRRSIGを抽出する', { timeout: TEST_TIMEOUT_MS }, async t => {
    const server = await startDnsServer(t, (query, transport) => transport === 'udp'
        ? { flags: dnsPacket.TRUNCATED_RESPONSE }
        : dnskeyResponse(query));
    let transportResult;
    const result = await getResourceRecord('example.test', LOCALHOST, 'DNSKEY', {
        dnsResponseCache: new Map(),
        queryDirectlyUDP: async (...args) => {
            transportResult = await server.query(...args);
            return transportResult;
        }
    });
    assert.deepEqual(server.queries.map(query => query.transport), ['udp', 'tcp']);
    for (const query of server.queries) assertDnssecQuery(query, 'DNSKEY');
    assert.equal(transportResult.transport, 'tcp');
    assert.equal(transportResult.isFallback, true);
    assert.equal(transportResult.retryFrom, 'udp-truncated');
    assert.equal(result.rcode, 'NOERROR');
    assert.equal(result.resourceRecords.length, 1);
    assert.equal(result.resourceRecords[0].name, 'example.test');
    assert.deepEqual(result.resourceRecords[0].data.key, Buffer.alloc(1312, 1));
    assert.equal(result.resourceRecords[0].data.algorithm, 18);
    assert.equal(result.rrsigRecords.length, 1);
    assert.deepEqual(result.rrsigRecords[0].data, dnskeyResponse(server.queries[1]).answers[1].data);
});

test('実リゾルバーの応答キャッシュはTTL内に再利用し、TTL経過後は再問い合わせする', { timeout: TEST_TIMEOUT_MS }, async t => {
    let now = Date.now();
    t.mock.method(Date, 'now', () => now);
    const server = await startDnsServer(t, query => ({
        answers: [{ name: query.questions[0].name, type: 'A', ttl: 1, data: '192.0.2.44' }]
    }));
    const options = { queryDirectlyUDP: server.query, dnsResponseCache: new Map() };
    const first = await getResourceRecord('cache.example.test', LOCALHOST, 'A', options);
    const cached = await getResourceRecord('cache.example.test', LOCALHOST, 'A', options);
    assert.deepEqual(cached, first);
    assert.equal(server.queries.length, 1);
    assert.equal(options.dnsResponseCache.size, 1);
    assert.equal([...options.dnsResponseCache.values()][0].expiresAt, now + 1000);
    now += 999;
    assert.deepEqual(await getResourceRecord('cache.example.test', LOCALHOST, 'A', options), first);
    assert.equal(server.queries.length, 1);
    now += 1;
    assert.deepEqual(await getResourceRecord('cache.example.test', LOCALHOST, 'A', options), first);
    assert.equal(server.queries.length, 2);
});

for (const transport of ['udp', 'tcp']) {
    test(`実リゾルバーの${transport.toUpperCase()}タイムアウトを問い合わせ失敗として扱う`, { timeout: TEST_TIMEOUT_MS }, async t => {
        const server = await startDnsServer(t, (query, receivedTransport) =>
            transport === 'tcp' && receivedTransport === 'udp'
                ? { flags: dnsPacket.TRUNCATED_RESPONSE }
                : null);
        let failure;
        await assert.rejects(getResourceRecord('timeout.example.test', LOCALHOST, 'A', {
            dnsResponseCache: new Map(),
            queryDirectlyUDP: async (domain, ip, cache, type, options) => {
                failure = await server.query(domain, ip, cache, type, { ...options, timeoutMs: 250 });
                return failure;
            }
        }), /DNSクエリ失敗: TIMEOUT/);
        assert.equal(failure.error, 'TIMEOUT');
        assert.equal(failure.transport, transport);
        assert.equal(failure.retryable, true);
        assert.equal(failure.name, 'timeout.example.test');
        assert.equal(failure.qType, 'A');
        assert.deepEqual(server.queries.map(query => query.transport), transport === 'udp' ? ['udp'] : ['udp', 'tcp']);
    });

    test(`実リゾルバーの進行中の${transport.toUpperCase()}問い合わせをAbortSignalで中断する`, { timeout: TEST_TIMEOUT_MS }, async t => {
        const controller = new AbortController();
        let cancel = true;
        const server = await startDnsServer(t, (query, receivedTransport) => {
            if (transport === 'tcp' && receivedTransport === 'udp') {
                return { flags: dnsPacket.TRUNCATED_RESPONSE };
            }
            if (cancel) {
                controller.abort(new Error('test cancellation'));
                return null;
            }
            return {
                answers: [{ name: query.questions[0].name, type: 'A', ttl: 60, data: '192.0.2.44' }]
            };
        });
        let failure;
        const cache = new Map();
        await assert.rejects(getResourceRecord('abort.example.test', LOCALHOST, 'A', {
            dnsResponseCache: cache,
            queryDirectlyUDP: async (domain, ip, cache, type, options) => {
                failure = await server.query(domain, ip, cache, type, { ...options, signal: controller.signal });
                return failure;
            }
        }), /DNSクエリ失敗: ABORTED/);
        assert.equal(failure.error, 'ABORTED');
        assert.equal(failure.retryable, false);
        assert.equal(failure.detail, 'test cancellation');
        assert.equal(cache.size, 0, 'Cancellation is not cached as a DNS failure');
        assert.deepEqual(server.queries.map(query => query.transport), transport === 'udp' ? ['udp'] : ['udp', 'tcp']);
        cancel = false;
        const retried = await getResourceRecord('abort.example.test', LOCALHOST, 'A', {
            dnsResponseCache: cache, queryDirectlyUDP: server.query
        });
        assert.equal(retried.resourceRecords[0].data, '192.0.2.44');
        assert.deepEqual(server.queries.map(query => query.transport),
            transport === 'udp' ? ['udp', 'udp'] : ['udp', 'tcp', 'udp', 'tcp']);
    });
}

test('模擬ルートから委任を辿り、ゾーン頂点とNSのIPv4アドレスを実通信で取得する', { timeout: TEST_TIMEOUT_MS }, async t => {
    const zone = 'integration.test';
    const childIp = '192.0.2.53';
    const child = await startDnsServer(t, query => ({
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        answers: query.questions[0].type === 'SOA'
            ? [{
                name: zone, type: 'SOA', ttl: 60,
                data: {
                    mname: `ns.${zone}`, rname: `hostmaster.${zone}`, serial: 1,
                    refresh: 3600, retry: 600, expire: 86400, minimum: 60
                }
            }]
            : [{ name: query.questions[0].name, type: 'A', ttl: 60, data: childIp }]
    }));
    const root = await startDnsServer(t, () => ({
        authorities: [{ name: zone, type: 'NS', ttl: 60, data: `ns.${zone}` }],
        additionals: [{ name: `ns.${zone}`, type: 'A', ttl: 60, data: childIp }]
    }));
    const destinations = [];
    const servers = new Map([[ROOT_SERVER_BOOTSTRAP_IP, root], [childIp, child]]);
    // Only the destination is redirected; encoding, transport, decoding and resolution stay real.
    const queryLocalAuthority = (domain, serverIp, cache, type, options) => {
        destinations.push({ serverIp, type });
        assert.ok(servers.has(serverIp), `Unexpected DNS destination: ${serverIp}`);
        return servers.get(serverIp).query(domain, LOCALHOST, cache, type, options);
    };
    const zoneInfo = await getZoneApex(`www.${zone}`, { queryDirectlyUDP: queryLocalAuthority });
    assert.equal(zoneInfo.zoneApex, zone);
    assert.equal(zoneInfo.parentNs, ROOT_SERVER_BOOTSTRAP_IP);
    assert.equal(zoneInfo.currentNs, childIp);
    assert.deepEqual(zoneInfo.childNameservers, [`ns.${zone}`]);
    assert.equal(await getARecord(`ns.${zone}`, {
        queryDirectlyUDP: queryLocalAuthority, dnsResponseCache: new Map()
    }), childIp);
    assert.deepEqual(destinations, [
        { serverIp: ROOT_SERVER_BOOTSTRAP_IP, type: 'SOA' },
        { serverIp: childIp, type: 'SOA' },
        { serverIp: ROOT_SERVER_BOOTSTRAP_IP, type: 'A' },
        { serverIp: childIp, type: 'A' }
    ]);
    assert.equal(root.queries.length, 2);
    assert.equal(child.queries.length, 2);
});
