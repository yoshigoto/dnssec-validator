#!/usr/bin/env python3
"""
dnssec-check.jp の掲載ドメイン全56件をローカルの DNSSEC バリデータ API に対し一括検証するテストスクリプト。

使い方:
    python3 test/validate_all_domains.py
    python3 test/validate_all_domains.py --url http://localhost:3002
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

CHECK_JP_URL = "https://www.dnssec-check.jp/"

def fetch_published_domains():
    """https://www.dnssec-check.jp/ からテスト用ドメイン一覧を抽出し、順序を維持したリストを返す"""
    print(f"[{CHECK_JP_URL}] から検証用ドメイン一覧を取得中...")
    try:
        req = urllib.request.Request(CHECK_JP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as res:
            html = res.read().decode("utf-8")
        
        domains = []
        for match in re.finditer(r'href="([^"]*[\?&]domain=[^"#&]+)"', html):
            parsed = urlparse(match.group(1))
            qs = parse_qs(parsed.query)
            if "domain" in qs and qs["domain"]:
                domain = qs["domain"][0]
                if domain not in domains:
                    domains.append(domain)
        
        if len(domains) > 0:
            print(f"  -> {len(domains)} 件のドメインを抽出しました。")
            return domains
    except Exception as e:
        print(f"  -> ページの取得に失敗しました ({e})。")
    
    print("  -> フォールバック用内蔵ドメインリストを使用します。")
    return [
        "success.rsasha256.dnssec-check.jp", "www.success.rsasha256.dnssec-check.jp",
        "keytag.ds.error.rsasha256.dnssec-check.jp", "www.keytag.ds.error.rsasha256.dnssec-check.jp",
        "hash.ds.error.rsasha256.dnssec-check.jp", "www.hash.ds.error.rsasha256.dnssec-check.jp",
        "sign.ds.error.rsasha256.dnssec-check.jp", "www.sign.ds.error.rsasha256.dnssec-check.jp",
        "sign.dnskey.error.rsasha256.dnssec-check.jp", "www.sign.dnskey.error.rsasha256.dnssec-check.jp",
        "expire.dnskey.error.rsasha256.dnssec-check.jp", "www.expire.dnskey.error.rsasha256.dnssec-check.jp",
        "success.ecdsap256sha256.dnssec-check.jp", "www.success.ecdsap256sha256.dnssec-check.jp",
        "keytag.ds.error.ecdsap256sha256.dnssec-check.jp", "www.keytag.ds.error.ecdsap256sha256.dnssec-check.jp",
        "hash.ds.error.ecdsap256sha256.dnssec-check.jp", "www.hash.ds.error.ecdsap256sha256.dnssec-check.jp",
        "sign.ds.error.ecdsap256sha256.dnssec-check.jp", "www.sign.ds.error.ecdsap256sha256.dnssec-check.jp",
        "sign.dnskey.error.ecdsap256sha256.dnssec-check.jp", "www.sign.dnskey.error.ecdsap256sha256.dnssec-check.jp",
        "expire.dnskey.error.ecdsap256sha256.dnssec-check.jp", "www.expire.dnskey.error.ecdsap256sha256.dnssec-check.jp",
        "success.ed25519.dnssec-check.jp", "www.success.ed25519.dnssec-check.jp",
        "keytag.ds.error.ed25519.dnssec-check.jp", "www.keytag.ds.error.ed25519.dnssec-check.jp",
        "hash.ds.error.ed25519.dnssec-check.jp", "www.hash.ds.error.ed25519.dnssec-check.jp",
        "sign.ds.error.ed25519.dnssec-check.jp", "www.sign.ds.error.ed25519.dnssec-check.jp",
        "sign.dnskey.error.ed25519.dnssec-check.jp", "www.sign.dnskey.error.ed25519.dnssec-check.jp",
        "expire.dnskey.error.ed25519.dnssec-check.jp", "www.expire.dnskey.error.ed25519.dnssec-check.jp",
        "success.ed448.dnssec-check.jp", "www.success.ed448.dnssec-check.jp",
        "keytag.ds.error.ed448.dnssec-check.jp", "www.keytag.ds.error.ed448.dnssec-check.jp",
        "hash.ds.error.ed448.dnssec-check.jp", "www.hash.ds.error.ed448.dnssec-check.jp",
        "sign.ds.error.ed448.dnssec-check.jp", "www.sign.ds.error.ed448.dnssec-check.jp",
        "sign.dnskey.error.ed448.dnssec-check.jp", "www.sign.dnskey.error.ed448.dnssec-check.jp",
        "expire.dnskey.error.ed448.dnssec-check.jp", "www.expire.dnskey.error.ed448.dnssec-check.jp",
        "corrupted.sign.a.error.rsasha256.dnssec-check.jp",
        "corrupted.sign.a.error.ecdsap256sha256.dnssec-check.jp",
        "corrupted.sign.a.error.ed25519.dnssec-check.jp",
        "corrupted.sign.a.error.ed448.dnssec-check.jp",
        "missing.cover.mismatch.nsec.rsasha256.dnssec-check.jp",
        "target.type.mismatch.nsec.rsasha256.dnssec-check.jp",
        "missing.cover.mismatch.nsec3.rsasha256.dnssec-check.jp",
        "target.type.mismatch.nsec3.rsasha256.dnssec-check.jp"
    ]

def validate_domain(target_url, domain, timeout=30):
    """単一のドメインに対して POST /api/validate を実行する"""
    endpoint = target_url.rstrip('/') + '/api/validate'
    payload = json.dumps({"domain": domain}).encode('utf-8')
    headers = {"Content-Type": "application/json"}
    
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method='POST')
    
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            data = json.loads(res.read().decode('utf-8'))
            elapsed = int((time.time() - t0) * 1000)
            return {
                "status": res.status,
                "success": data.get("success", False),
                "error": data.get("error"),
                "logs": data.get("logs", []),
                "elapsed": elapsed
            }
    except urllib.error.HTTPError as e:
        elapsed = int((time.time() - t0) * 1000)
        try:
            data = json.loads(e.read().decode('utf-8'))
            return {
                "status": e.code,
                "success": data.get("success", False),
                "error": data.get("error"),
                "logs": data.get("logs", []),
                "elapsed": elapsed
            }
        except Exception:
            return {"status": e.code, "success": False, "error": str(e), "logs": [], "elapsed": elapsed}
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return {"status": 500, "success": False, "error": str(e), "logs": [], "elapsed": elapsed}

def run_isolated_validation(domain, project_root, timeout=30):
    """アプリ内レートリミットを回避するため独立した Node プロセスを起動して1件検証する"""
    node_code = f"""
const {{ app }} = require('./dnssec-validator.js');
const server = app.listen(0, '127.0.0.1', async () => {{
    const port = server.address().port;
    try {{
        const res = await fetch('http://127.0.0.1:' + port + '/api/validate', {{
            method: 'POST',
            headers: {{ 'content-type': 'application/json' }},
            body: JSON.stringify({{ domain: '{domain}' }})
        }});
        const json = await res.json();
        console.log(JSON.stringify({{ status: res.status, data: json }}));
    }} catch (err) {{
        console.log(JSON.stringify({{ status: 500, error: err.message }}));
    }} finally {{
        server.close();
        process.exit(0);
    }}
}});
"""
    t0 = time.time()
    try:
        proc = subprocess.run(
            ["node", "-e", node_code],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        elapsed = int((time.time() - t0) * 1000)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout.strip().splitlines()[-1])
            data = raw.get("data", {})
            return {
                "status": raw.get("status", 500),
                "success": data.get("success", False),
                "error": data.get("error") or raw.get("error"),
                "logs": data.get("logs", []),
                "elapsed": elapsed
            }
        else:
            return {"status": 500, "success": False, "error": proc.stderr or "プロセス実行エラー", "logs": [], "elapsed": elapsed}
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return {"status": 500, "success": False, "error": str(e), "logs": [], "elapsed": elapsed}

def main():
    parser = argparse.ArgumentParser(description="dnssec-check.jp 掲載ドメイン一括検証テストスクリプト")
    parser.add_argument("--url", help="対象 API のベース URL (指定がある場合は既存サーバーに直接クエリ)")
    parser.add_argument("--timeout", type=int, default=30, help="各ドメイン検証のタイムアウト (秒)")
    args = parser.parse_args()

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    domains = fetch_published_domains()

    print(f"\n--- 検証開始 ({len(domains)} 件) ---")
    start_time = time.time()
    
    results = []
    
    for idx, domain in enumerate(domains, 1):
        expected_success = domain.startswith("success.") or domain.startswith("www.success.")
        
        if args.url:
            res = validate_domain(args.url, domain, timeout=args.timeout)
        else:
            res = run_isolated_validation(domain, project_root, timeout=args.timeout)
            
        actual_success = res["success"]
        is_match = (actual_success == expected_success)
        
        results.append({
            "domain": domain,
            "expected": expected_success,
            "actual": actual_success,
            "match": is_match,
            "res": res
        })
        
        status_str = "✓ PASSED" if is_match else "✗ FAILED"
        exp_str = "SUCCESS" if expected_success else "FAILURE"
        act_str = "SUCCESS" if actual_success else "FAILURE"
        
        print(f"[{idx:2d}/{len(domains)}] {status_str} | {domain:<62s} | 期待:{exp_str:<7s} | 実際:{act_str:<7s} ({res['elapsed']}ms)")

    total = len(results)
    passed_count = sum(1 for r in results if r["match"])
    failed_count = total - passed_count
    total_elapsed = time.time() - start_time

    print("\n" + "=" * 80)
    print(f"検証サマリー (所要時間: {total_elapsed:.1f}秒)")
    print(f"  合計: {total} 件 | 成功(一致): {passed_count} 件 | 失敗(不一致): {failed_count} 件")
    print("=" * 80)

    if failed_count > 0:
        print("\n--- 不一致ドメイン詳細 ---")
        for r in results:
            if not r["match"]:
                print(f"- {r['domain']}")
                print(f"    期待値: {r['expected']} | 実際の判定: {r['actual']} (HTTP Status: {r['res']['status']})")
                if r['res']['error']:
                    print(f"    Error: {r['res']['error']}")
                if r['res']['logs']:
                    print("    Logs:")
                    for log in r['res']['logs']:
                        print(f"      - {log}")
        sys.exit(1)
    else:
        print("\nすべてのドメインで期待通りの成功/失敗判定となりました。")
        sys.exit(0)

if __name__ == "__main__":
    main()
