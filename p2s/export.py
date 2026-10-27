"""Finding exports for other systems (--formats nessus,sarif,defectdojo,findings).

nessus      Nessus v2 XML: most vulnerability-management and reporting platforms import it. Stable pluginID per advisory
            and finding kind, CVE ids in <cve> and also in the title (some importers drop <cve>), one URL in <see_also>
            (some importers read only the first), abstract description, concrete host data only in plugin_output.
sarif       SARIF 2.1.0 (code-scanning style dashboards).
defectdojo  DefectDojo "Generic Findings Import" JSON.
findings    php2shell.findings/1: stable, documented JSON for scripts and agents (docs/findings.schema.json).
Only assets that need action become findings. No CVSS vector is invented: one is emitted only when the advisory has it
(PHP2Shell: NVD primary CVSS 3.1, the higher of the two CVEs, since one finding covers both)."""
import hashlib
import json
from xml.sax.saxutils import escape, quoteattr

from . import __version__
from . import assets as A
from . import classify as C

NESSUS_SEV = {"critical": 4, "high": 3, "medium": 2}
DOJO_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "ok": "Info", "info": "Info"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}

TEXT = {
    "tr": {
        "vuln_title": "PHP2Shell: PHP Çekirdeğinde Kimlik Doğrulamasız Uzaktan Kod Çalıştırma ({cves})",
        "vuln_desc": "Sunucuda çalışan PHP sürümü, PHP çekirdeğindeki use-after-free / bayat istek durumu hatalarından (PHP2Shell, {cves}) "
                     "etkilenmektedir. Bu hatalar, uygulama kodundan bağımsız olarak kimlik doğrulaması gerektirmeden uzaktan kod "
                     "çalıştırmaya imkân vermektedir.",
        "vuln_impact": "Saldırgan, kimlik doğrulaması olmadan sunucuda PHP sürecinin yetkileriyle komut çalıştırabilir; uygulama verileri, "
                       "veritabanı kimlik bilgileri ve oturum anahtarları ele geçirilebilir.",
        "vuln_fix": "PHP'nin {fixed} veya üzeri sürümlere ya da CVE kayıtlarını içeren dağıtım paketine yükseltilmesi, ardından PHP-FPM / "
                    "Apache süreçlerinin tamamen durdurulup yeniden başlatılması tavsiye edilir.",
        "verify_title": "PHP2Shell ({cves}) Açısından Doğrulanması Gereken PHP Kurulumu",
        "verify_desc": "Sunucuda PHP kullanıldığı tespit edilmiş, ancak sürümün PHP2Shell ({cves}) yamasını içerip içermediği uzaktan "
                       "kesinleştirilememiştir (sürüm gizli veya dağıtım paketi sürüm numarasını değiştirmeden yamalanmış olabilir).",
        "verify_fix": "Sunucu üzerinde PHP paket sürümünün ve paket değişiklik kaydında ilgili CVE kayıtlarının kontrol edilmesi; "
                      "yamasızsa {fixed} veya üzeri sürüme yükseltilmesi tavsiye edilir.",
        "fpm_title": "Ağdan Erişilebilir PHP-FPM (FastCGI) Servisi",
        "fpm_desc": "PHP-FPM (FastCGI) servisi ağ üzerinden doğrudan erişilebilir durumdadır. FastCGI protokolü istemciye çalıştırılacak "
                    "betiği ve PHP ayarlarını belirleme imkânı verdiğinden, bu servise erişebilen bir saldırgan yama seviyesinden "
                    "bağımsız olarak sunucuda kod çalıştırabilir.",
        "fpm_impact": "Kimlik doğrulaması olmadan sunucuda kod çalıştırılabilir ve sunucu tamamen ele geçirilebilir.",
        "fpm_fix": "PHP-FPM'in yalnızca 127.0.0.1 veya unix soketi üzerinden dinleyecek şekilde yapılandırılması, ilgili portun "
                   "güvenlik duvarında kapatılması ve sunucunun ele geçirilme açısından incelenmesi tavsiye edilir.",
        "ioc_title": "PHP Sunucusunda Ele Geçirilme Göstergeleri",
        "ioc_desc": "Sunucu üzerinde yapılan salt okunur incelemede web kök dizinlerinde, oturum dosyalarında veya PHP süreçlerinde "
                    "yetkisiz kod çalıştırıldığına işaret eden göstergeler tespit edilmiştir.",
        "ioc_impact": "Sunucu ele geçirilmiş olabilir; kalıcı arka kapı, veri sızıntısı ve iç ağa yayılma riski bulunmaktadır.",
        "ioc_fix": "Sunucunun ağdan yalıtılması, olay müdahalesi sürecinin başlatılması, göstergelerin incelenmesi ve sunucudaki tüm "
                   "kimlik bilgilerinin ve anahtarların yenilenmesi tavsiye edilir.",
        "impact": "Etki", "evidence": "Elde edilen bilgiler",
    },
    "en": {
        "vuln_title": "PHP2Shell: Unauthenticated Remote Code Execution in PHP Core ({cves})",
        "vuln_desc": "The PHP version running on the server is affected by the use-after-free / stale request state flaws in PHP core "
                     "(PHP2Shell, {cves}), which allow unauthenticated remote code execution independent of the application code.",
        "vuln_impact": "An attacker can run commands with the privileges of the PHP process without authentication and obtain application "
                       "data, database credentials and session keys.",
        "vuln_fix": "Upgrade PHP to {fixed} or later, or to the distribution package that lists the CVEs, then fully stop and start "
                    "PHP-FPM / Apache.",
        "verify_title": "PHP Installation To Verify For PHP2Shell ({cves})",
        "verify_desc": "PHP is in use but whether it contains the PHP2Shell ({cves}) fix could not be established remotely (version hidden, "
                       "or a distribution package patched without changing the version string).",
        "verify_fix": "Check the PHP package version and its changelog for the CVE ids on the host; if unpatched, upgrade to {fixed} or later.",
        "fpm_title": "PHP-FPM (FastCGI) Service Reachable From The Network",
        "fpm_desc": "The PHP-FPM (FastCGI) service is directly reachable over the network. FastCGI lets the client choose the script and PHP "
                    "settings, so anyone who reaches it can run code regardless of the patch level.",
        "fpm_impact": "Unauthenticated code execution and full compromise of the server.",
        "fpm_fix": "Bind PHP-FPM to 127.0.0.1 or a unix socket, close the port at the firewall and review the host for compromise.",
        "ioc_title": "Indicators Of Compromise On A PHP Server",
        "ioc_desc": "A read-only review of the host found indicators of unauthorized code execution in web roots, session files or PHP processes.",
        "ioc_impact": "The host may be compromised: persistent backdoors, data exfiltration and lateral movement are possible.",
        "ioc_fix": "Isolate the host, start incident response, review the indicators and rotate every credential and key on the host.",
        "impact": "Impact", "evidence": "Evidence",
    },
}
VERIFY_STATUSES = {"VERIFY_DISTRO_BACKPORT", "PHP_VERSION_HIDDEN"}


def texts(lang):
    """Finding text: built-in PHP2Shell wording, overridden per key by the advisory's "texts": {"tr": {...}, "en": {...}}."""
    return dict(TEXT[lang], **(C.ADVISORY.get("texts", {}).get(lang) or {}))


def _fixed():
    return " / ".join(C.ADVISORY.get("fixed", {}).values())


def _kind(status):
    if status == "FPM_EXPOSED":
        return "fpm"
    return "verify" if status in VERIFY_STATUSES else "vuln"


def _kinds(a):
    """{kind: (worst status, endpoint)} for one asset. A host-verified PHP verdict replaces the banner verdicts of its
    web endpoints; an exposed FastCGI port and IoC hits are findings of their own next to the PHP one."""
    eps = a.get("endpoints") or []
    out = {}
    fpm = [e for e in eps if e.get("status") == "FPM_EXPOSED"]
    if fpm:
        out["fpm"] = ("FPM_EXPOSED", fpm[0])
    if a["final_status"].startswith("VERIFIED_"):
        php = [(a["final_status"], next((e for e in eps if e.get("status") != "FPM_EXPOSED"), {}))]
    else:
        php = [(e["status"], e) for e in eps if e.get("status") != "FPM_EXPOSED"] or [(a["final_status"], {})]
    php = [(st, e) for st, e in php if C.is_actionable(st) and st != "FPM_EXPOSED"]
    if php:
        st, e = min(php, key=lambda x: C.rank(x[0]))
        out[_kind(st)] = (st, e)
    if a.get("closure") == "COMPROMISE_SUSPECTED":
        out = {"ioc": (a["final_status"], eps[0] if eps else {}), **out}
    return out


def findings(assets, lang="tr"):
    """Findings for every asset that needs action: one per kind (vuln | verify, fpm, ioc)."""
    t, cves = texts(lang), ", ".join(C.CVES)
    out = []
    for a in assets:
        if not A.needs_action(a):
            continue
        v = a.get("verified") or {}
        for k, (st, ep) in _kinds(a).items():
            sev = "critical" if k in ("ioc", "fpm") else C.severity(st)
            details = [f"{C.status_label(st, lang)}", f"{C.closure_label(a.get('closure', ''), lang)}"]
            if a.get("php_versions"):
                details.append("PHP " + ", ".join(a["php_versions"]))
            if ep.get("port"):
                details.append(f"port {ep['port']}/{ep.get('scheme') or 'tcp'}")
            details.append(a.get("note", "") if st == a["final_status"] else "")
            if v.get("summary"):
                details.append(v["summary"])
            if k == "ioc":
                details += (v.get("ioc") or {}).get("hits", [])
            out.append({
                "id": hashlib.sha256(f"php2shell|{C.ADVISORY.get('id', '')}|{k}|{a['host']}".encode()).hexdigest()[:32],
                "kind": k, "check_id": f"php2shell-{C.ADVISORY.get('id', 'advisory')}-{k}", "host": a["host"],
                "names": a.get("names") or a.get("dns_names") or [], "port": ep.get("port") or 0,
                "scheme": ep.get("scheme") or "", "severity": sev, "status": st, "closure": a.get("closure", ""),
                "cves": list(C.CVES) if k in ("vuln", "verify") else [],
                "title": t[f"{k}_title"].format(cves=cves), "description": t[f"{k}_desc"].format(cves=cves),
                "impact": t.get(f"{k}_impact", t["vuln_impact"]), "remediation": t[f"{k}_fix"].format(fixed=_fixed()),
                "evidence": " · ".join(x for x in details if x), "references": [u for _, u in C.ADVISORY.get("sources", [])],
                "labels": a.get("labels", {}),
            })
    return out


def nessus(assets, lang="tr"):
    """Nessus v2 XML (see the module docstring for the importer-friendly choices)."""
    fs = findings(assets, lang)
    by_host = {}
    for f in fs:
        by_host.setdefault(f["host"], []).append(f)
    vec, score = C.ADVISORY.get("cvss3_vector", ""), C.ADVISORY.get("cvss3_score")
    out = ['<?xml version="1.0" ?>', "<NessusClientData_v2>", f"<Report name={quoteattr('php2shell-scanner ' + __version__)}>"]
    for host, items in by_host.items():
        out.append(f"<ReportHost name={quoteattr(host)}><HostProperties><tag name=\"host-ip\">{escape(host)}</tag>"
                   + (f"<tag name=\"host-fqdn\">{escape(items[0]['names'][0])}</tag>" if items[0]["names"] else "")
                   + "</HostProperties>")
        for f in items:
            title = f["title"] if all(c in f["title"] for c in f["cves"]) else f"{f['title']} ({', '.join(f['cves'])})"
            proto = "tcp"
            out.append(
                f"<ReportItem port=\"{int(f['port'])}\" svc_name={quoteattr(f['scheme'] or 'www')} protocol=\"{proto}\" "
                f"severity=\"{NESSUS_SEV.get(f['severity'], 2)}\" pluginID={quoteattr(f['check_id'])} pluginName={quoteattr(title)} "
                f"pluginFamily=\"Web Servers\">"
                f"<description>{escape(f['description'] + ' ' + TEXT[lang]['impact'] + ': ' + f['impact'])}</description>"
                f"<solution>{escape(f['remediation'])}</solution><risk_factor>{escape(f['severity'].title())}</risk_factor>"
                f"<plugin_output>{escape(f['evidence'] + ((' · ' + ', '.join(f['cves'])) if f['cves'] else ''))}</plugin_output>"
                + "".join(f"<cve>{escape(c)}</cve>" for c in f["cves"])
                + (f"<cvss3_vector>{escape(vec)}</cvss3_vector>" if vec and f["cves"] else "")
                + (f"<cvss3_base_score>{float(score):.1f}</cvss3_base_score>" if score is not None and vec and f["cves"] else "")
                # one URL: some importers read only the first <see_also> and collapse its whitespace into a single reference
                + f"<see_also>{escape(([f'https://nvd.nist.gov/vuln/detail/{c}' for c in f['cves']] + f['references'] + [''])[0])}</see_also>"
                + "</ReportItem>")
        out.append("</ReportHost>")
    out += ["</Report>", "</NessusClientData_v2>"]
    return "\n".join(out) + "\n"


def sarif(assets, lang="en"):
    fs = findings(assets, lang)
    rules = {}
    for f in fs:
        rules.setdefault(f["check_id"], {"id": f["check_id"], "name": f["kind"], "shortDescription": {"text": f["title"]},
                                         "fullDescription": {"text": f["description"]}, "help": {"text": f["remediation"]},
                                         "properties": {"tags": ["security"] + f["cves"]}})
    results = [{"ruleId": f["check_id"], "level": SARIF_LEVEL.get(f["severity"], "warning"),
                "message": {"text": f"{f['title']}: {f['evidence']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"{f['scheme'] or 'tcp'}://{f['host']}:{f['port']}/"}}}],
                "partialFingerprints": {"php2shell/v1": f["id"]},
                "properties": {"status": f["status"], "closure": f["closure"], "severity": f["severity"]}} for f in fs]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "php2shell-scanner", "version": __version__, "informationUri":
                                          "https://github.com/erdemkayar/php2shell-scan", "rules": list(rules.values())}},
                      "results": results}]}


def defectdojo(assets, lang="en"):
    fs = findings(assets, lang)
    return {"findings": [{
        "title": f["title"], "description": f"{f['description']}\n\n{f['evidence']}", "severity": DOJO_SEV.get(f["severity"], "Medium"),
        "mitigation": f["remediation"], "impact": f["impact"], "references": "\n".join(f["references"]),
        "cve": f["cves"][0] if f["cves"] else None, "vulnerability_ids": [{"vulnerability_id": c} for c in f["cves"]],
        "unique_id_from_tool": f["id"], "vuln_id_from_tool": f["check_id"], "active": True,
        "verified": f["status"].startswith("VERIFIED") or f["kind"] in ("ioc", "fpm") or f["status"] == "ORACLE_VULNERABLE",
        "static_finding": False, "dynamic_finding": True,
        "endpoints": [{"host": f["host"], "port": f["port"], "protocol": f["scheme"] or None}],
    } for f in fs]}


def findings_doc(assets, summary, meta, lang="en"):
    """php2shell.findings/1 (schema: docs/findings.schema.json)."""
    return {"format": "php2shell.findings/1", "tool_version": __version__, "advisory": C.ADVISORY.get("id", ""),
            "cves": list(C.CVES), "generated": meta.get("generated", ""), "complete": meta.get("complete"),
            "summary": {k: summary[k] for k in ("assets", "actionable", "verified", "by_status", "by_closure") if k in summary},
            "findings": findings(assets, lang)}


def write(fmt, path, assets, summary, meta, lang):
    if fmt == "nessus":
        open(path, "w", encoding="utf-8").write(nessus(assets, lang))
    else:
        doc = {"sarif": lambda: sarif(assets, lang), "defectdojo": lambda: defectdojo(assets, lang),
               "findings": lambda: findings_doc(assets, summary, meta, lang)}[fmt]()
        json.dump(doc, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
