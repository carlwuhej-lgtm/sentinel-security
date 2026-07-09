"""
哨兵安全平台 — CVE 同步服务

从 NVD (National Vulnerability Database) 同步真实 CVE 数据，
存入本地数据库，供扫描器和漏洞管理模块引用。

功能:
- 全量同步：拉取 NVD JSON 数据（按年份）
- 增量同步：仅拉取最近 N 天的更新
- 本地查询：按 CVE ID / CWE / 关键词查询
- 自动关联：扫描结果自动匹配已知 CVE

参考:
- NVD API: https://nvd.nist.gov/developers/vulnerability-key
- CVE 官网: https://cve.mitre.org/
"""

import os
import json
import sqlite3
import time
import gzip
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import requests

# ─── 配置 ────────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # 可选，有则速率更高
CVE_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "cve_cache")
# ────────────────────────────────────────────────────────────────────────────────


def _get_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """获取数据库连接。"""
    if db_path is None:
        db_path = os.environ.get(
            "SENTINEL_DB_PATH",
            os.path.join(os.path.dirname(__file__), "..", "sentinel.db")
        )
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_cve_tables(db: Optional[sqlite3.Connection] = None) -> None:
    """初始化 CVE 缓存表。"""
    own_db = db is None
    if own_db:
        db = _get_db()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id          TEXT PRIMARY KEY,
            source           TEXT    DEFAULT 'NVD',
            severity         TEXT    DEFAULT '',
            cvss_score      REAL    DEFAULT 0,
            cvss_version    TEXT    DEFAULT '3.1',
            cwe_ids         TEXT    DEFAULT '',
            description      TEXT    DEFAULT '',
            published_date   TEXT    DEFAULT '',
            last_modified   TEXT    DEFAULT '',
            references_json  TEXT    DEFAULT '[]',
            patch_available INTEGER DEFAULT 0,
            exploit_present INTEGER DEFAULT 0,
            created_at       TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at       TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache(severity);
        CREATE INDEX IF NOT EXISTS idx_cve_cache_cwe      ON cve_cache(cwe_ids);
        CREATE INDEX IF NOT EXISTS idx_cve_cache_published ON cve_cache(published_date);

        CREATE TABLE IF NOT EXISTS cve_affected_packages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id     TEXT    NOT NULL,
            ecosystem    TEXT    DEFAULT '',
            package_name TEXT    DEFAULT '',
            version_range TEXT    DEFAULT '',
            fixed_version TEXT    DEFAULT '',
            created_at   TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (cve_id) REFERENCES cve_cache(cve_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_cve_pkgs_cve ON cve_affected_packages(cve_id);
    """)
    if own_db:
        db.commit()
        db.close()


def _nvd_api_headers() -> Dict[str, str]:
    """构造 NVD API 请求头。"""
    headers = {"User-Agent": "SentinelSecurityPlatform/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_cves_by_cwe(cwe_id: str, max_results: int = 20) -> List[Dict[str, Any]]:
    """
    按 CWE ID 从 NVD 查询相关 CVE。
    返回: [{"cve_id": "...", "cvss_score": 9.8, "description": "..."}]
    """
    init_cve_tables()
    db = _get_db()
    try:
        rows = db.execute(
            "SELECT cve_id, severity, cvss_score, cwe_ids, description, published_date"
            "  FROM cve_cache"
            "  WHERE cwe_ids LIKE ?"
            "  ORDER BY cvss_score DESC, published_date DESC"
            "  LIMIT ?",
            (f"%{cwe_id}%", max_results)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def fetch_cve_detail(cve_id: str) -> Optional[Dict[str, Any]]:
    """查询单个 CVE 的详细信息（先从本地缓存，miss 则查 NVD）。"""
    init_cve_tables()
    db = _get_db()
    try:
        row = db.execute("SELECT * FROM cve_cache WHERE cve_id=?", (cve_id,)).fetchone()
        if row:
            return dict(row)

        # Miss → 从 NVD API 拉取单个 CVE
        return _fetch_single_cve_from_nvd(cve_id, db)
    finally:
        db.close()


def _fetch_single_cve_from_nvd(cve_id: str, db: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """从 NVD API 拉取单个 CVE 并缓存。"""
    try:
        url = f"{NVD_API_BASE}/{cve_id}"
        resp = requests.get(url, headers=_nvd_api_headers(), timeout=30)
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_data = vulns[0].get("cve", {})
        _store_cve_in_db(db, cve_data)
        db.commit()
        row = db.execute("SELECT * FROM cve_cache WHERE cve_id=?", (cve_id,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"[CVESync] Failed to fetch {cve_id}: {e}")
        return None


def sync_recent_cves(days: int = 7, results_per_page: int = 2000) -> int:
    """
    增量同步最近 N 天的 CVE。
    返回: 新入库的 CVE 数量。
    """
    init_cve_tables()
    db = _get_db()
    try:
        count = 0
        start_index = 0
        last_mod_start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

        print(f"[CVESync] 增量同步最近 {days} 天（自 {last_mod_start}）...")

        while True:
            url = (f"{NVD_API_BASE}"
                   f"?lastModStartDate={last_mod_start}"
                   f"&resultsPerPage={results_per_page}&startIndex={start_index}")
            try:
                resp = requests.get(url, headers=_nvd_api_headers(), timeout=60)
                if resp.status_code != 200:
                    print(f"[CVESync] API 返回 {resp.status_code}，停止同步")
                    break
                data = resp.json()
            except Exception as e:
                print(f"[CVESync] 请求失败: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                cve_data = v.get("cve", {})
                if _store_cve_in_db(db, cve_data):
                    count += 1

            total_results = data.get("totalResults", 0)
            start_index += len(vulns)
            db.commit()
            print(f"[CVESync] 进度: {start_index}/{total_results}，新增 {count} 条")

            if start_index >= total_results:
                break

            # 速率限制
            time.sleep(1.0 if NVD_API_KEY else 6.0)

        print(f"[CVESync] 增量同步完成，新增 {count} 条 CVE")
        return count
    finally:
        db.close()


def sync_year_cves(year: int) -> int:
    """
    同步指定年份的全部 CVE（全量同步）。
    注意：全量同步数据量大，建议仅首次运行时使用。
    """
    init_cve_tables()
    db = _get_db()
    try:
        count = 0
        start_index = 0
        results_per_page = 2000

        pub_start = f"{year}-01-01T00:00:00.000Z"
        pub_end   = f"{year}-12-31T23:59:59.999Z"

        print(f"[CVESync] 全量同步 {year} 年 CVE（{pub_start} ~ {pub_end}）...")

        while True:
            url = (f"{NVD_API_BASE}"
                   f"?pubStartDate={pub_start}&pubEndDate={pub_end}"
                   f"&resultsPerPage={results_per_page}&startIndex={start_index}")
            try:
                resp = requests.get(url, headers=_nvd_api_headers(), timeout=60)
                if resp.status_code != 200:
                    print(f"[CVESync] API 返回 {resp.status_code}，停止")
                    break
                data = resp.json()
            except Exception as e:
                print(f"[CVESync] 请求失败: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                cve_data = v.get("cve", {})
                if _store_cve_in_db(db, cve_data):
                    count += 1

            total_results = data.get("totalResults", 0)
            start_index += len(vulns)
            db.commit()
            print(f"[CVESync] 进度: {start_index}/{total_results}，入库 {count} 条")

            if start_index >= total_results:
                break
            time.sleep(1.0 if NVD_API_KEY else 6.0)

        print(f"[CVESync] {year} 年同步完成，入库 {count} 条 CVE")
        return count
    finally:
        db.close()


def _store_cve_in_db(db: sqlite3.Connection, cve_data: Dict) -> bool:
    """
    将 NVD CVE 数据存入本地缓存。
    返回: True（新入库）/ False（已存在或失败）。
    """
    try:
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return False

        # 已存在？
        exists = db.execute("SELECT 1 FROM cve_cache WHERE cve_id=?", (cve_id,)).fetchone()
        if exists:
            # 更新 last_modified
            last_mod = cve_data.get("lastModified", "")
            db.execute(
                "UPDATE cve_cache SET updated_at=datetime('now','localtime'),"
                "  last_modified=? WHERE cve_id=?",
                (last_mod, cve_id)
            )
            return False

        # 解析 CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_version = "3.1"
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                severity = m.get("baseSeverity", "").lower()
                cvss_version = "3.1" if "31" in key else ("3.0" if "30" in key else "2.0")
                break

        # 解析 CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    val = desc.get("value", "")
                    if "CWE-" in val:
                        # 提取 CWE-XXX
                        import re
                        cwes = re.findall(r"CWE-\d+", val)
                        cwe_ids.extend(cwes)
        cwe_str = ",".join(dict.fromkeys(cwe_ids))  # 去重

        # 描述
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")[:500]
                break

        # 发布日期
        published = cve_data.get("published", "")
        last_mod = cve_data.get("lastModified", "")

        # 引用链接
        refs = cve_data.get("references", [])
        ref_urls = [r.get("url", "") for r in refs[:5]]

        # 补丁/利用标记
        patch_available = 0
        exploit_present = 0
        for r in refs:
            tags = r.get("tags", [])
            if "Patch" in tags or "Fix" in tags:
                patch_available = 1
            if "Exploit" in tags or "PoC" in tags:
                exploit_present = 1

        # 入库
        db.execute(
            """INSERT INTO cve_cache
               (cve_id, severity, cvss_score, cvss_version, cwe_ids,
                description, published_date, last_modified, references_json,
                patch_available, exploit_present)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (cve_id, severity, cvss_score, cvss_version, cwe_str,
             description, published, last_mod, json.dumps(ref_urls),
             patch_available, exploit_present)
        )
        return True
    except Exception as e:
        print(f"[CVESync] 存储 CVE 失败: {e}")
        return False


def search_cves(keyword: str, severity: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    """
    按关键词搜索本地 CVE 缓存。
    参数:
        keyword: 搜索关键词（匹配 description）
        severity: 严重性过滤（critical/high/medium/low）
        limit: 返回数量上限
    """
    init_cve_tables()
    db = _get_db()
    try:
        sql = "SELECT * FROM cve_cache WHERE description LIKE ?"
        params: List[Any] = [f"%{keyword}%"]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)
        rows = db.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def get_cve_stats() -> Dict[str, Any]:
    """返回 CVE 缓存统计信息。"""
    init_cve_tables()
    db = _get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        by_severity = {}
        for r in db.execute("SELECT severity, COUNT(*) as cnt FROM cve_cache GROUP BY severity").fetchall():
            by_severity[r[0]] = r[1]
        latest = db.execute(
            "SELECT cve_id, published_date FROM cve_cache ORDER BY published_date DESC LIMIT 1"
        ).fetchone()
        return {
            "total": total,
            "by_severity": by_severity,
            "latest_cve": dict(latest) if latest else {},
        }
    finally:
        db.close()


def ensure_cwe_top25(db: Optional[sqlite3.Connection] = None) -> None:
    """
    确保 CWE Top 25 (2023) 对应的典型 CVE 已入库。
    如果本地无数据，则从 NVD 查询并缓存。
    """
    CWE_TOP25 = [
        "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78",
        "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-434",
        "CWE-86", "CWE-476", "CWE-287", "CWE-190", "CWE-502",
        "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306",
        # 补充 OWASP Top 10 相关
        "CWE-285", "CWE-327", "CWE-295", "CWE-200", "CWE-489",
        "CWE-16", "CWE-639", "CWE-942", "CWE-400", "CWE-1321",
    ]
    for cwe in CWE_TOP25:
        existing = fetch_cves_by_cwe(cwe, max_results=1)
        if not existing:
            print(f"[CVESync] {cwe} 无本地缓存，尝试从 NVD 同步...")
            # 搜索该 CWE 相关的 recent CVE
            try:
                url = f"{NVD_API_BASE}?keywordSearch={cwe}&resultsPerPage=5"
                resp = requests.get(url, headers=_nvd_api_headers(), timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    db_local = _get_db()
                    for v in data.get("vulnerabilities", []):
                        _store_cve_in_db(db_local, v.get("cve", {}))
                    db_local.commit()
                    db_local.close()
                    print(f"[CVESync] {cwe}: 缓存了 {len(data.get('vulnerabilities', []))} 条")
                time.sleep(1.0 if NVD_API_KEY else 6.0)
            except Exception as e:
                print(f"[CVESync] {cwe} 同步失败: {e}")
        else:
            print(f"[CVESync] {cwe}: 已有 {len(existing)} 条缓存")


# ─── CLI 入口 ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel CVE 同步服务")
    parser.add_argument("--recent", type=int, default=0,
                        help="增量同步最近 N 天的 CVE")
    parser.add_argument("--year", type=int, default=0,
                        help="全量同步指定年份的 CVE")
    parser.add_argument("--ensure-cwe-top25", action="store_true",
                        help="确保 CWE Top 25 的典型 CVE 已缓存")
    parser.add_argument("--search", type=str, default="",
                        help="按关键词搜索本地 CVE 缓存")
    parser.add_argument("--stats", action="store_true",
                        help="显示 CVE 缓存统计")
    args = parser.parse_args()

    if args.recent:
        sync_recent_cves(days=args.recent)
    elif args.year:
        sync_year_cves(year=args.year)
    elif args.ensure_cwe_top25:
        ensure_cwe_top25()
    elif args.search:
        results = search_cves(args.search, limit=10)
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif args.stats:
        print(json.dumps(get_cve_stats(), indent=2, ensure_ascii=False))
    else:
        print("Usage: python cve_sync_service.py --recent 7  (同步最近7天)")
        print("       python cve_sync_service.py --year 2023  (同步2023全年)")
        print("       python cve_sync_service.py --ensure-cwe-top25")
        print("       python cve_sync_service.py --search 'SQL injection'")
        print("       python cve_sync_service.py --stats")
