import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';

import { JSDOM, VirtualConsole } from 'jsdom';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../dnssec-validator-client.js', import.meta.url), 'utf8');
const NOW = Date.UTC(2026, 9, 23, 12);
const NOW_SECONDS = NOW / 1000;
const SAVED_DOMAIN_KEY = 'dnssec-validator-domain';

function makeResult(status = 'secure') {
    const signature = { keyTag: 1234, algorithm: 15, expiration: NOW_SECONDS + 10 * 86400, verified: true };
    return {
        success: status === 'secure', status,
        statusLabel: {
            secure: 'Secure（検証成功）', insecure: 'Insecure（未署名の委任）',
            bogus: 'Bogus（DNSSEC検証失敗）', indeterminate: '判定不能（検証データ不足）'
        }[status],
        logs: [], nextChecks: ['署名と委任を確認してください。'],
        diagram: {
            parent: {
                name: 'example.test', server: 'ns.parent.test',
                ds: [{ keyTag: 1234, algorithm: 15, digest: 'abcd' }],
                dnskey: [{ flags: 256, keyTag: 4321, algorithm: 15 }],
                rrsig: [{ ...signature, typeCovered: 'DS' }], dsAbsenceProof: null
            },
            child: {
                name: 'example.test', server: 'ns.child.test',
                dnskey: [{ flags: 257, keyTag: 1234, algorithm: 15 }],
                rrsig: [{ ...signature, typeCovered: 'DNSKEY' }],
                aRecordValidation: {
                    queried: true, recordType: 'AAAA', recordsFound: true,
                    signatures: [{ ...signature, trustChainVerified: true }],
                    trustChain: { dsMatchedKskKeyTags: [1234], dnskeyRrsetSignatures: [{ kskKeyTag: 1234 }] }
                }
            },
            checks: { dsKeyMatch: true, dsSignature: true, dnskeySignature: true },
            authorityChecks: null, dsProposal: null
        }
    };
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function waitForResult(ui) {
    const deadline = Date.now() + 2000;
    while (ui.element('statusBox').classList.contains('status-loading')) {
        assert.ok(Date.now() < deadline, 'Client did not finish handling the API response');
        await setImmediate();
    }
}

function createUi(t, { search = '', savedDomain, storageUnavailable = false, respond = () => jsonResponse(makeResult()) } = {}) {
    const errors = [];
    const virtualConsole = new VirtualConsole();
    virtualConsole.on('jsdomError', error => errors.push(error));
    const dom = new JSDOM(html, {
        url: `http://localhost/dnssec-validator/${search}`,
        runScripts: 'outside-only', virtualConsole
    });
    const { window } = dom;
    t.after(() => {
        window.close();
        assert.deepEqual(errors, [], 'Unexpected client errors');
    });
    window.Date.now = () => NOW;
    if (savedDomain !== undefined) window.localStorage.setItem(SAVED_DOMAIN_KEY, savedDomain);
    if (storageUnavailable) {
        Object.defineProperty(window, 'localStorage', {
            get() { throw new window.DOMException('Storage is disabled', 'SecurityError'); }
        });
    }
    const requests = [];
    const alerts = [];
    window.alert = message => alerts.push(message);
    window.fetch = (url, options) => {
        requests.push({ url, ...options, payload: JSON.parse(options.body) });
        return respond(url, options);
    };
    window.eval(script);
    return {
        window, requests, alerts,
        element: id => window.document.getElementById(id),
        async submit(domain = 'example.test', recordType = 'AAAA') {
            window.document.getElementById('domain').value = domain;
            window.document.getElementById('recordType').value = recordType;
            const event = new window.Event('submit', { cancelable: true, bubbles: true });
            window.document.getElementById('validateForm').dispatchEvent(event);
            assert.equal(event.defaultPrevented, true);
            await waitForResult(this);
        }
    };
}

test('HTMLのランドマーク、フォームラベル、リスト、結果表が意味的に正しく構成される', () => {
    const document = new JSDOM(html).window.document;
    const ids = [...document.querySelectorAll('[id]')].map(element => element.id);

    assert.equal(document.querySelectorAll('main').length, 1);
    assert.equal(new Set(ids).size, ids.length);
    assert.ok([...document.querySelectorAll('label[for]')].every(label => document.getElementById(label.htmlFor)));
    assert.ok([...document.querySelectorAll('ul, ol')].every(list => [...list.children].every(child => child.tagName === 'LI')));
    assert.equal(document.querySelector('#statusBox').getAttribute('aria-live'), 'polite');
    assert.ok(document.querySelector('#authorityChecks table caption'));
});

test('画面の全8種の選択肢から種別とURLのホスト名をAPIへ送る', async t => {
    const ui = createUi(t);
    assert.equal(ui.requests.length, 0);
    const types = [...ui.element('recordType').options].map(option => option.value);
    assert.deepEqual(types, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SRV']);
    for (const type of types) {
        await ui.submit('  https://www.example.test:8443/path?q=1  ', type);
        const request = ui.requests.at(-1);
        assert.equal(request.url, './api/validate');
        assert.equal(request.method, 'POST');
        assert.deepEqual({ ...request.headers }, { 'Content-Type': 'application/json' });
        assert.deepEqual(request.payload, { domain: 'www.example.test', recordType: type });
    }
});

test('Englishリンクで英語表示に切り替わり、日本語へ戻るリンクが検証条件を保つ', async t => {
    const ui = createUi(t, { search: '?lang=en&domain=url.example.test&recordType=mx' });
    await waitForResult(ui);
    assert.equal(ui.window.document.documentElement.lang, 'en');
    assert.equal(ui.window.document.title, 'DNSSEC Delegation Validator');
    assert.equal(ui.element('englishNote').hidden, false);
    assert.equal(ui.element('languageLink').textContent, '日本語');
    assert.equal(ui.element('languageLink').getAttribute('href'), '/dnssec-validator/?domain=url.example.test&recordType=mx');
    assert.equal(ui.element('validateForm').querySelector('button').textContent, 'Start validation');
    assert.equal(ui.element('statusBox').innerText, 'Secure (validation succeeded)');
    const rolloverSteps = ui.element('dsProposal').querySelectorAll('ol li');
    assert.equal(rolloverSteps.length, 3);
    assert.match(rolloverSteps[0].textContent, /DS for the new key is registered with the parent/);
    assert.match(ui.window.document.querySelector('#authorityChecks table caption').textContent, /Authoritative server response comparison/);
    assert.match(ui.element('childARecordValidation').textContent, /DNSSEC validation for AAAA record/);
    assert.match(ui.element('childARecordValidation').textContent, /Chain of trust: secure/);

    const japanese = createUi(t);
    assert.equal(japanese.element('languageLink').textContent, 'English');
    assert.equal(japanese.element('languageLink').getAttribute('href'), '/dnssec-validator/?lang=en');
    assert.equal(japanese.window.document.documentElement.lang, 'ja');
});

test('English表示で不在証明の結果も英語で表示する', async t => {
    const result = makeResult();
    result.diagram.child.aRecordValidation.recordsFound = false;
    result.diagram.child.aRecordValidation.signatures = [];
    result.diagram.child.aRecordValidation.denialProof = {
        rcode: 'NOERROR', type: 'NSEC3', verified: true,
        records: [{ name: 'example.test', type: 'NSEC3', expiration: NOW_SECONDS + 86400 }]
    };
    const ui = createUi(t, { search: '?lang=en', respond: () => jsonResponse(result) });
    await ui.submit();
    assert.match(ui.element('childARecordValidation').textContent, /NSEC3 proof for AAAA record absence: Passed/);
});

test('空入力は警告してAPIを呼ばず、入力時はドメインを保存する', async t => {
    const ui = createUi(t);
    await ui.submit('  ');
    assert.equal(ui.requests.length, 0);
    assert.deepEqual(ui.alerts, ['ドメイン名を入力してください']);
    ui.element('domain').value = '  example.test  ';
    ui.element('domain').dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.window.localStorage.getItem(SAVED_DOMAIN_KEY), 'example.test');
});

test('URLパラメーターを保存値より優先し、種別を正規化して自動検証する', async t => {
    const ui = createUi(t, { search: '?domain=url.example.test&recordType=mx', savedDomain: 'saved.example.test' });
    await waitForResult(ui);
    assert.equal(ui.element('domain').value, 'url.example.test');
    assert.equal(ui.element('recordType').value, 'MX');
    assert.deepEqual(ui.requests.map(request => request.payload), [{ domain: 'url.example.test', recordType: 'MX' }]);
});

test('保存ドメインを復元して自動検証し、未対応のURL種別はAのままにする', async t => {
    const ui = createUi(t, { search: '?recordType=INVALID', savedDomain: 'saved.example.test' });
    await waitForResult(ui);
    assert.equal(ui.element('domain').value, 'saved.example.test');
    assert.deepEqual(ui.requests[0].payload, { domain: 'saved.example.test', recordType: 'A' });
});

test('localStorageが利用できなくてもURLから検証でき、入力時にも例外を出さない', async t => {
    const ui = createUi(t, { search: '?domain=url.example.test', storageUnavailable: true });
    await waitForResult(ui);
    ui.element('domain').dispatchEvent(new ui.window.Event('input'));
    assert.equal(ui.requests[0].payload.domain, 'url.example.test');
    assert.equal(ui.element('statusBox').classList.contains('status-success'), true);
});

for (const [status, className] of [
    ['secure', 'status-success'], ['insecure', 'status-insecure'],
    ['bogus', 'status-failed'], ['indeterminate', 'status-indeterminate']
]) {
    test(`${status}のAPI応答を状態ラベル・スタイルへ反映する`, async t => {
        const result = makeResult(status);
        result.logs = status === 'secure' ? [] : ['確認用ログ'];
        const ui = createUi(t, { respond: () => jsonResponse(result) });
        await ui.submit();
        assert.equal(ui.element('statusBox').className, `result-status-box ${className}`);
        // jsdom has no layout engine; read the same innerText property the client writes.
        assert.equal(ui.element('statusBox').innerText, result.statusLabel);
        assert.equal(ui.element('diagram').style.display, 'block');
        assert.equal(ui.element('nextChecksBox'), null);
        assert.equal(ui.element('validation-error-details').style.display, status === 'secure' ? 'none' : 'block');
        assert.match(ui.element('childARecordValidation').textContent, /AAAAレコードDNSSEC検証/);
        assert.match(ui.element('childARecordValidation').textContent, /信頼の連鎖: 成功/);
        assert.match(ui.element('chainArrow').textContent, /ハッシュ一致/);
    });
}

test('JSONエラー・HTTP 429の詳細を表示する', async t => {
    const ui = createUi(t, { respond: () => jsonResponse({
        error: 'リクエスト制限に達しました。', logs: ['60秒後に再試行'],
        nextChecks: ['時間をおいて再試行してください。']
    }, 429) });
    await ui.submit();
    assert.equal(ui.element('statusBox').innerText, '判定不能（エラー）');
    assert.equal(ui.element('statusBox').classList.contains('status-indeterminate'), true);
    assert.match(ui.element('validation-error-details').textContent, /リクエスト制限.*\n60秒後/);
});

for (const [kind, respond, expected] of [
    ['非JSON応答', () => new Response('<html>Gateway timeout</html>', {
        status: 504, headers: { 'Content-Type': 'text/html' }
    }), /HTTP 504/],
    ['不正JSON', () => new Response('{', { headers: { 'Content-Type': 'application/json' } }), /詳細:/],
    ['通信失敗', () => Promise.reject(new TypeError('Network unavailable')), /Network unavailable/]
]) {
    test(`${kind}を成功扱いせず、通信エラーと詳細を表示する`, async t => {
        const ui = createUi(t, { respond });
        await ui.submit();
        assert.equal(ui.element('statusBox').innerText, '判定不能（通信エラー）');
        assert.equal(ui.element('statusBox').classList.contains('status-indeterminate'), true);
        assert.equal(ui.element('validation-error-details').style.display, 'block');
        assert.match(ui.element('validation-error-details').textContent, expected);
        assert.equal(ui.element('nextChecksBox'), null);
        assert.doesNotMatch(ui.element('diagram').textContent, /Gateway timeout/);
    });
}

test('再検証中に前回のエラー・比較表・提案を消し、完了後に新しい結果を表示する', async t => {
    let resolveResponse;
    const previous = { ...makeResult('bogus'), logs: ['前回のエラー'] };
    previous.diagram.authorityChecks = { parent: {
        ds: { complete: true, consistent: true, servers: [{ name: 'old.example.test', records: ['old DS'], status: 'ok' }] }
    } };
    previous.diagram.dsProposal = { parentDs: [], cds: { status: 'absent' }, notes: ['古い提案'] };
    let response = jsonResponse(previous);
    const ui = createUi(t, { respond: () => response });
    await ui.submit();
    assert.equal(ui.element('validation-error-details').style.display, 'block');
    assert.match(ui.element('authorityChecksBody').textContent, /old.example.test/);
    assert.match(ui.element('dsProposalContent').textContent, /古い提案/);
    response = new Promise(resolve => { resolveResponse = resolve; });
    const submitted = ui.submit('next.example.test', 'MX');
    assert.equal(ui.element('statusBox').classList.contains('status-loading'), true);
    assert.match(ui.element('statusBox').innerText, /検証中/);
    assert.equal(ui.element('validation-error-details').textContent, '');
    assert.equal(ui.element('validation-error-details').style.display, 'none');
    assert.equal(ui.element('authorityChecks').style.display, 'none');
    assert.equal(ui.element('dsProposal').style.display, 'none');
    assert.equal(ui.element('authorityChecksBody').children.length, 0);
    assert.equal(ui.element('dsProposalContent').children.length, 0);
    assert.match(ui.element('zoneApexSummary').textContent, /next.example.test/);
    resolveResponse(jsonResponse(makeResult()));
    await submitted;
    assert.equal(ui.element('statusBox').classList.contains('status-success'), true);
});

test('タイムアウトと未知の状態は成功扱いにせず判定不能として表示する', async t => {
    const result = { ...makeResult('indeterminate'), timedOut: true, statusLabel: '判定不能（タイムアウト）' };
    const ui = createUi(t, { respond: () => jsonResponse(result) });
    await ui.submit();
    assert.equal(ui.element('statusBox').innerText, '判定不能（タイムアウト）');
    assert.equal(ui.element('statusBox').classList.contains('status-indeterminate'), true);
    result.status = 'unknown';
    delete result.statusLabel;
    await ui.submit();
    assert.equal(ui.element('statusBox').innerText, '判定不能');
    assert.equal(ui.element('statusBox').classList.contains('status-indeterminate'), true);
});

test('証明不足の診断と観測NSEC/NSEC3、対象署名の欠落・取得エラーを表示する', async t => {
    const result = makeResult('bogus');
    const validation = result.diagram.child.aRecordValidation;
    validation.recordsFound = false;
    validation.signatures = [];
    validation.denialProof = {
        verified: false, type: '', diagnostics: ['証明が不足しています'],
        observedNsec: [{ name: 'a.example.test', nextDomain: 'z.example.test' }],
        observedNsec3: [{ ownerHash: 'ABC', nextHash: 'DEF', iterations: 1, salt: 'A1B2' }]
    };
    const ui = createUi(t, { respond: () => jsonResponse(result) });
    await ui.submit();
    for (const text of ['証明が不足しています', '応答NSEC: a.example.test -> z.example.test', '応答NSEC3: ABC -> DEF', 'iteration 1 / salt A1B2']) {
        assert.ok(ui.element('childARecordValidation').textContent.includes(text), text);
    }
    validation.recordsFound = true;
    await ui.submit();
    assert.match(ui.element('childARecordValidation').textContent, /AAAAレコードへのRRSIGの探索: 失敗/);
    validation.error = 'DNSKEY timeout';
    await ui.submit();
    assert.match(ui.element('childARecordValidation').textContent, /検証できませんでした: DNSKEY timeout/);
});

test('署名期限のJST日時と7日境界・期限切れ・不明を表示し、警告を強調する', async t => {
    const result = makeResult();
    const ui = createUi(t, { respond: () => jsonResponse(result) });
    for (const [remaining, warning, expired] of [
        [7 * 86400 + 1, false, false], [7 * 86400, true, false],
        [1, true, false], [0, false, true], [-1, false, true], [null, false, false]
    ]) {
        const expiration = remaining === null ? null : NOW_SECONDS + remaining;
        result.diagram.child.rrsig[0].expiration = expiration;
        await ui.submit();
        const node = ui.element('childRrsig');
        assert.equal(node.querySelectorAll('.signature-expiring').length, warning ? 1 : 0);
        assert.equal(node.textContent.includes('期限切れ'), expired);
        if (expiration === null) {
            assert.doesNotMatch(node.textContent, /期限日時|Invalid Date/);
        } else {
            const expected = new Intl.DateTimeFormat('ja-JP', {
                dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Asia/Tokyo'
            }).format(new Date(expiration * 1000));
            assert.ok(node.textContent.includes(`期限日時 ${expected} JST`));
        }
    }
});

for (const type of ['NSEC', 'NSEC3']) {
    test(`${type}のNODATA・NXDOMAIN・証明失敗と親DS不在を表示する`, async t => {
        const result = makeResult();
        const validation = result.diagram.child.aRecordValidation;
        validation.recordsFound = false;
        validation.signatures = [];
        validation.denialProof = {
            rcode: 'NOERROR', type, verified: true,
            records: [{ name: 'example.test', type, expiration: NOW_SECONDS + 86400 }]
        };
        result.diagram.parent.ds = [];
        result.diagram.parent.dsAbsenceProof = { verified: true, type, records: [], diagnostics: ['親DSなし'] };
        const ui = createUi(t, { respond: () => jsonResponse(result) });
        await ui.submit();
        assert.match(ui.element('childARecordValidation').textContent, new RegExp(`${type}によるAAAAレコード不在証明: 成功`));
        assert.match(ui.element('parentDs').textContent, /DSなし（親側不在証明: 検証成功）/);
        assert.match(ui.element('chainArrow').textContent, /ハッシュ照合対象なし/);
        validation.denialProof.rcode = 'NXDOMAIN';
        validation.denialProof.verified = false;
        await ui.submit();
        assert.match(ui.element('childARecordValidation').textContent, new RegExp(`${type}による名前不在証明: 失敗`));
        assert.equal(ui.element('childARecordValidation').querySelectorAll('.signature-failed').length, 1);
    });
}

test('権威サーバーの一致・差分・未確認と応答失敗、CDS/CDNSKEY提案を表示する', async t => {
    const result = makeResult();
    const comparison = {
        complete: true, consistent: true, hasDifferences: false,
        servers: [{ name: 'ns.example.test', ip: '192.0.2.53', status: 'ok', records: ['Key Tag 1234'], rcode: 'NOERROR' }]
    };
    result.diagram.authorityChecks = {
        parent: {
            nameservers: comparison,
            ds: { ...comparison, consistent: false, hasDifferences: true }
        },
        child: {
            nameservers: { complete: false, consistent: false, hasDifferences: false, servers: [
                { name: 'ns.failed.test', status: 'error', error: 'TIMEOUT' }
            ] },
            dnskey: comparison
        }
    };
    const ds = { keyTag: 5678, algorithm: 18, digestType: 2, digest: 'cdef' };
    result.diagram.dsProposal = {
        parentDs: [ds], cds: { status: 'different', toAdd: [ds], toRemove: [ds] },
        cdnskey: { status: 'error', error: 'SERVFAIL' }, notes: ['自動変更しません']
    };
    const ui = createUi(t, { respond: () => jsonResponse(result) });
    await ui.submit();
    const table = ui.element('authorityChecksBody');
    assert.equal(ui.element('authorityChecks').style.display, 'block');
    assert.equal(table.querySelectorAll('.status-consistent').length, 2);
    assert.equal(table.querySelectorAll('.status-difference').length, 1);
    assert.equal(table.querySelectorAll('.status-incomplete').length, 1);
    assert.match(table.textContent, /取得失敗: TIMEOUT/);
    assert.match(table.textContent, /192.0.2.53/);
    const proposal = ui.element('dsProposalContent');
    assert.equal(ui.element('dsProposal').style.display, 'block');
    for (const text of ['親DSと差分あり', '子の提案のみ', '親の登録のみ', '取得・解析失敗 (SERVFAIL)', '自動変更しません', 'ML-DSA-44']) {
        assert.ok(proposal.textContent.includes(text), text);
    }
});

test('API由来の文字列はHTMLにせず、制御文字と表示長を制限する', async t => {
    const payload = '<img src=x onerror="window.injected=true">';
    const result = makeResult('bogus');
    result.logs = [payload + '\u0000' + 'x'.repeat(2100)];
    result.nextChecks = [payload];
    result.diagram.parent.server = payload;
    result.diagram.child.aRecordValidation.signatures[0].verified = false;
    result.diagram.child.aRecordValidation.signatures[0].reason = payload;
    const ui = createUi(t, { respond: () => jsonResponse(result) });
    await ui.submit();
    assert.ok(ui.element('validation-error-details').textContent.startsWith(payload));
    assert.equal(ui.element('validation-error-details').textContent.length, 2000);
    assert.equal(ui.element('validation-error-details').textContent.includes('\u0000'), false);
    assert.match(ui.element('childARecordValidation').textContent, /失敗理由:/);
    assert.equal(ui.window.document.querySelectorAll('img, [onerror]').length, 0);
    assert.equal(ui.window.injected, undefined);
    assert.equal(ui.element('parentZoneTitle').querySelector('.identifier').textContent, payload);
});
