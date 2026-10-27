"""Version parsing, status model and PHP/CMS fingerprinting (no network I/O here)."""
import json
import pkgutil
import re
from urllib.parse import urljoin, urlparse

# Advisory data (fixed releases, CVE ids, distro baselines, sources) lives in advisory.json so a new PHP
# advisory is a data change, not a code change. set_advisory() swaps it at runtime (--advisory FILE).
ADVISORY, CVES, FIXED, EOL_BELOW, FROZEN, DISTRO_BRANCHES = {}, [], {}, (8, 2), {}, {}


def _ver_tuple(s):
    return tuple(int(x) for x in s.split("."))


def set_advisory(adv):
    global ADVISORY, CVES, FIXED, EOL_BELOW, FROZEN, DISTRO_BRANCHES
    for k in ("id", "cves", "fixed"):
        if k not in adv:
            raise ValueError(f"advisory: missing '{k}'")
    ADVISORY = adv
    CVES = list(adv["cves"])
    FIXED = {_ver_tuple(b): _ver_tuple(v)[2] for b, v in adv["fixed"].items()}
    EOL_BELOW = _ver_tuple(adv.get("eol_below", min(adv["fixed"], key=_ver_tuple)))
    FROZEN = {}
    for k, v in adv.get("distro_frozen_versions", {}).items():
        if k.startswith("_"):
            continue
        v = {"distro": v} if isinstance(v, str) else v
        FROZEN[k] = {"distro": v.get("distro", "a distribution"), "requires_hint": bool(v.get("requires_hint"))}
    DISTRO_BRANCHES = {k.lower(): set(v) for k, v in adv.get("distro_branches", {}).items() if not k.startswith("_")}


def validate_advisory(adv):
    """(errors, warnings) for an advisory document before it is used (--check-advisory)."""
    err, warn = [], []
    ver, br, day = re.compile(r"^\d+\.\d+\.\d+$"), re.compile(r"^\d+\.\d+$"), re.compile(r"^\d{4}-\d{2}-\d{2}$")
    if not isinstance(adv, dict):
        return ["advisory must be a JSON object"], []
    for k in ("id", "cves", "fixed"):
        if k not in adv:
            err.append(f"missing '{k}'")
    if not isinstance(adv.get("id", ""), str) or not adv.get("id"):
        err.append("'id' must be a non-empty string")
    cves = adv.get("cves", [])
    if not isinstance(cves, list) or not cves or not all(isinstance(c, str) and re.match(r"^CVE-\d{4}-\d{4,}$", c) for c in cves):
        err.append("'cves' must be a non-empty list of CVE-YYYY-NNNN ids")
    fixed = adv.get("fixed", {})
    if not isinstance(fixed, dict) or not fixed:
        err.append("'fixed' must map branch 'X.Y' -> first fixed release 'X.Y.Z'")
    else:
        for b, v in fixed.items():
            if not br.match(str(b)) or not ver.match(str(v)) or not str(v).startswith(f"{b}."):
                err.append(f"fixed: '{b}' -> '{v}' is not 'X.Y' -> 'X.Y.Z' on the same branch")
    eol = adv.get("eol_below")
    if eol is not None and not br.match(str(eol)):
        err.append("'eol_below' must be 'X.Y'")
    elif eol and isinstance(fixed, dict) and fixed and all(br.match(str(b)) for b in fixed):
        if min(fixed, key=_ver_tuple) != eol:
            warn.append(f"eol_below {eol} differs from the oldest fixed branch {min(fixed, key=_ver_tuple)}: "
                        "branches in between are treated as vulnerable with no upstream fix")
    if adv.get("published") and not day.match(str(adv["published"])):
        err.append("'published' must be YYYY-MM-DD")
    elif not adv.get("published"):
        warn.append("no 'published' date: --ioc defaults to 60 days back instead of publication - 30 days")
    for k, v in adv.get("distro_frozen_versions", {}).items():
        if not k.startswith("_") and not ver.match(k):
            err.append(f"distro_frozen_versions: key '{k}' is not X.Y.Z")
    for k, v in adv.get("distro_branches", {}).items():
        if not k.startswith("_") and (not isinstance(v, list) or not all(br.match(str(x)) for x in v)):
            err.append(f"distro_branches: '{k}' must be a list of 'X.Y'")
    if adv.get("cvss3_vector") and not str(adv["cvss3_vector"]).startswith("CVSS:3."):
        err.append("'cvss3_vector' must be a CVSS 3.x vector (importers compute severity from it)")
    sc = adv.get("cvss3_score")
    if sc is not None and (not isinstance(sc, (int, float)) or not 0 <= sc <= 10):
        err.append("'cvss3_score' must be a number 0-10")
    if sc is not None and not adv.get("cvss3_vector"):
        err.append("'cvss3_score' needs 'cvss3_vector'")
    if adv.get("oracle") not in (None, "session-write"):
        err.append("'oracle' may only be 'session-write' (the validated PHP2Shell behavioural check) or absent")
    for lang, tx in (adv.get("texts") or {}).items():
        if lang not in ("tr", "en") or not isinstance(tx, dict) or not all(isinstance(v, str) for v in tx.values()):
            err.append(f"texts: '{lang}' must be 'tr'/'en' mapping text keys to strings")
    srcs = adv.get("sources", [])
    if not srcs:
        warn.append("no 'sources': the report's method section will list none")
    for s in srcs:
        if not (isinstance(s, list) and len(s) == 2 and str(s[1]).startswith("https://")):
            err.append(f"sources: {s!r} must be [name, https-url]")
    return err, warn


def load_advisory(path=None):
    raw = open(path, "rb").read() if path else pkgutil.get_data(__package__ or "p2s", "advisory.json")
    set_advisory(json.loads(raw))


load_advisory()

VER_RE = re.compile(r"(?<![A-Za-z])PHP[/ ](\d+)\.(\d+)\.(\d+)([^\s;,)\"']*)", re.I)  # not 'CakePHP/4.4.1' 
# Vendor builds that backport fixes without touching the version string (RHEL family keeps plain "8.2.13").
HINT_RE = re.compile(r"(ubuntu|debian|centos|red ?hat|rhel|almalinux|rocky|oracle ?linux|amazon ?linux|amzn|\bel[6-9]\b|suse|sles|fedora)", re.I)
DISTRO_RE = re.compile(r"(ubuntu|deb\d|debian|\+deb|~deb|\.el\d|\bel\d|amzn|\+b\d|\.ph\d)", re.I)
# Third-party repos that ship UPSTREAM point releases (no silent backports): their version string is authoritative.
UPSTREAM_REPO_RE = re.compile(r"(sury|remi)", re.I)

# status -> (rank, severity)  rank 0 = most urgent; actionable = rank <= ACTIONABLE_MAX
STATUS = {
    "FPM_EXPOSED":                (0, "critical"),
    "VERIFIED_VULNERABLE":        (1, "critical"),
    "ORACLE_VULNERABLE":          (2, "critical"),
    "VERIFIED_RESTART_REQUIRED":  (3, "high"),
    "LIKELY_VULNERABLE":          (4, "high"),
    "EOL_NO_UPSTREAM_FIX":        (5, "high"),
    "VERIFY_DISTRO_BACKPORT":     (6, "medium"),
    "PHP_VERSION_HIDDEN":         (7, "medium"),
    "PATCHED_BY_BANNER":          (8, "ok"),
    "ORACLE_PATCHED":             (9, "ok"),
    "VERIFIED_PATCHED":           (10, "ok"),
    "NO_WEB_RESPONSE":            (11, "info"),
    "NO_PHP_INDICATOR":           (12, "info"),
    "VERIFIED_NO_PHP":            (13, "info"),
}
ACTIONABLE_MAX = 7


def rank(status):
    return STATUS.get(status, (99, "info"))[0]


def severity(status):
    return STATUS.get(status, (99, "info"))[1]


def is_actionable(status):
    return rank(status) <= ACTIONABLE_MAX


I18N_STATUS = {
    "en": {
        "FPM_EXPOSED": ("PHP-FPM / FastCGI reachable from the network",
                        "Close the port now (bind FPM to 127.0.0.1 or a unix socket, firewall it): a reachable FastCGI socket is remote "
                        "code execution regardless of patch level. Then patch PHP and treat the host as possibly compromised."),
        "VERIFIED_VULNERABLE": ("Verified vulnerable (host check)",
                                "Upgrade PHP to a fixed release (or install the vendor package that lists the CVEs), then restart PHP-FPM/Apache."),
        "ORACLE_VULNERABLE": ("Vulnerable (behavioural check, running PHP)",
                              "The running PHP answered like a pre-fix build: upgrade (or install the vendor package that lists the CVEs) and restart workers. Also turn off display_errors/display_startup_errors."),
        "VERIFIED_RESTART_REQUIRED": ("Patched on disk, still running old code",
                                      "Restart PHP-FPM / Apache / FrankenPHP workers; the running process still uses the pre-patch binary. "
                                      "Apache mod_php: full stop/start (systemctl restart), graceful/reload is not enough."),
        "LIKELY_VULNERABLE": ("Likely vulnerable (banner)",
                              "Confirm on the host, then upgrade to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later and restart workers."),
        "EOL_NO_UPSTREAM_FIX": ("End-of-life PHP, no upstream fix",
                                "Migrate to a supported branch (>= 8.2) or obtain a vendor backport; apply interim mitigations until then."),
        "VERIFY_DISTRO_BACKPORT": ("Below fixed version, distro build (verify)",
                                   "Check the distro advisory / package changelog for CVE-2026-109618 and -109619; the fix may be backported without a version change."),
        "PHP_VERSION_HIDDEN": ("PHP present, version hidden",
                               "Run the SSH verification (php -v, package version) or ask the asset owner; treat as exposed until proven patched."),
        "PATCHED_BY_BANNER": ("Patched version (banner)", "No action; consider hiding X-Powered-By."),
        "ORACLE_PATCHED": ("Patched (behavioural check, running PHP)",
                           "No patch action. Turn off display_errors/display_startup_errors: the server prints PHP warnings to clients."),
        "VERIFIED_PATCHED": ("Verified patched (host check)", "No action."),
        "NO_WEB_RESPONSE": ("Open port, no HTTP(S) answer (not assessed)",
                            "Not assessed by the banner scan (TLS/protocol error or non-HTTP service). Verify on the host (--verify) or check how the service is exposed."),
        "NO_PHP_INDICATOR": ("No PHP indicator", "No action. Absence of a banner is not proof of absence."),
        "VERIFIED_NO_PHP": ("Verified: no PHP on host", "No action."),
    },
    "tr": {
        "FPM_EXPOSED": ("PHP-FPM / FastCGI ağdan erişilebilir",
                        "Portu hemen kapatın (FPM'i 127.0.0.1'e veya unix socket'e bağlayın, firewall): erişilebilir FastCGI soketi yama "
                        "seviyesinden bağımsız olarak uzaktan kod çalıştırmadır. Ardından PHP'yi yamalayın ve host'u ele geçirilmiş olabilir kabul edin."),
        "VERIFIED_VULNERABLE": ("Doğrulanmış savunmasız (host kontrolü)",
                                "PHP'yi düzeltilmiş sürüme yükseltin (veya CVE'leri listeleyen vendor paketini kurun), ardından PHP-FPM/Apache'yi yeniden başlatın."),
        "ORACLE_VULNERABLE": ("Savunmasız (davranış kontrolü, çalışan PHP)",
                              "Çalışan PHP yama öncesi build gibi yanıt verdi: yükseltin (veya CVE'leri listeleyen vendor paketini kurun) ve worker'ları yeniden başlatın. display_errors/display_startup_errors'ı da kapatın."),
        "VERIFIED_RESTART_REQUIRED": ("Diskte yamalı, çalışan süreç eski",
                                      "PHP-FPM / Apache / FrankenPHP worker'larını yeniden başlatın; çalışan süreç hâlâ yama öncesi binary'yi kullanıyor. "
                                      "Apache mod_php: tam stop/start (systemctl restart); graceful/reload yetmez."),
        "LIKELY_VULNERABLE": ("Muhtemelen savunmasız (banner)",
                              "Host üzerinde doğrulayın; 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 veya üstüne yükseltip worker'ları yeniden başlatın."),
        "EOL_NO_UPSTREAM_FIX": ("Destek dışı PHP, upstream yama yok",
                                "Desteklenen bir branch'e (>= 8.2) geçin veya vendor backport'u alın; o zamana kadar geçici önlemleri uygulayın."),
        "VERIFY_DISTRO_BACKPORT": ("Düzeltilmiş sürümün altında, distro build (doğrulanmalı)",
                                   "Distro advisory'si / paket changelog'unda CVE-2026-109618 ve -109619 var mı kontrol edin; yama sürüm değişmeden backport edilmiş olabilir."),
        "PHP_VERSION_HIDDEN": ("PHP var, sürüm gizli",
                               "SSH doğrulaması (php -v, paket sürümü) çalıştırın veya varlık sahibine sorun; yamalı olduğu kanıtlanana kadar maruz kabul edin."),
        "PATCHED_BY_BANNER": ("Yamalı sürüm (banner)", "Aksiyon gerekmez; X-Powered-By başlığını gizlemeyi değerlendirin."),
        "ORACLE_PATCHED": ("Yamalı (davranış kontrolü, çalışan PHP)",
                           "Yama aksiyonu gerekmez. display_errors/display_startup_errors'ı kapatın: sunucu PHP uyarılarını istemciye basıyor."),
        "VERIFIED_PATCHED": ("Doğrulanmış yamalı (host kontrolü)", "Aksiyon gerekmez."),
        "NO_WEB_RESPONSE": ("Port açık, HTTP(S) yanıtı yok (değerlendirilmedi)",
                            "Banner taramasıyla değerlendirilemedi (TLS/protokol hatası veya HTTP olmayan servis). Host üzerinde doğrulayın (--verify) veya servisin nasıl yayınlandığını kontrol edin."),
        "NO_PHP_INDICATOR": ("PHP göstergesi yok", "Aksiyon gerekmez. Banner'ın olmaması PHP'nin olmadığını kanıtlamaz."),
        "VERIFIED_NO_PHP": ("Doğrulandı: host'ta PHP yok", "Aksiyon gerekmez."),
    },
}


# Remediation closure per asset (p2s.assets.closure): order = report order, value = (severity, en, tr)
CLOSURE = {
    "COMPROMISE_SUSPECTED": ("critical", "Compromise suspected (IoC hits)", "Ele geçirilme şüphesi (IoC bulgusu)"),
    "OPEN": ("high", "Open", "Açık"),
    "OPEN_MITIGATED": ("medium", "Open, interim mitigation active", "Açık, geçici önlem aktif"),
    "PENDING_RESTART": ("medium", "Patched, restart pending", "Yamalı, yeniden başlatma bekliyor"),
    "CLOSED_REMOTE": ("ok", "Closed (remote evidence only)", "Kapandı (yalnız uzaktan kanıt)"),
    "CLOSED_IOC_PENDING": ("ok", "Closed on host, IoC check pending", "Host'ta kapandı, IoC kontrolü bekliyor"),
    "CLOSED_VERIFIED": ("ok", "Closed and verified (patched, running, no IoC)", "Kanıtlı kapandı (yamalı, çalışan süreç, IoC yok)"),
    "NO_PHP_EVIDENCE": ("info", "No PHP evidence", "PHP kanıtı yok"),
    "NOT_APPLICABLE": ("info", "Not applicable (no PHP)", "Kapsam dışı (PHP yok)"),
}


def closure_label(c, lang="en"):
    v = CLOSURE.get(c)
    return (v[2] if lang == "tr" else v[1]) if v else c


def status_label(status, lang="en"):
    return I18N_STATUS.get(lang, I18N_STATUS["en"]).get(status, (status, ""))[0]


def status_action(status, lang="en"):
    return I18N_STATUS.get(lang, I18N_STATUS["en"]).get(status, ("", ""))[1]


def classify_version(maj, mino, patch, suffix="", hint=""):
    """(status, confidence, note) for a PHP version.
    suffix: build string after the version (e.g. '-1ubuntu0.5'); hint: other banner text such as the Server header.
    Distro builds are flagged for verification instead of being called vulnerable, because vendors backport fixes
    without changing the version (observed: Ubuntu 24.04 ships the fix in a build that still reports 8.3.6)."""
    ver = f"{maj}.{mino}.{patch}"
    fixed = FIXED.get((maj, mino))
    if fixed is not None and patch >= fixed:
        return "PATCHED_BY_BANNER", "medium", f"{ver} >= fixed {maj}.{mino}.{fixed}."
    if fixed is None and (maj, mino) > max(FIXED):
        return "PATCHED_BY_BANNER", "low", f"Branch {maj}.{mino} is newer than the fixed series in the advisory; verify manually."
    why = []
    if UPSTREAM_REPO_RE.search(suffix or ""):  # ppa:ondrej / remi: the number is the real upstream version
        suffix, hint = "", ""
    if DISTRO_RE.search(suffix or ""):
        why.append(f"distro build string '{suffix}'")
    m = HINT_RE.search(hint or "")
    ships = DISTRO_BRANCHES.get(m.group(0).lower()) if m else None
    if m and ships is not None and f"{maj}.{mino}" not in ships:
        m = None  # e.g. official php Docker image: Apache '(Debian)', PHP built from upstream on a branch Debian never shipped
    if m:
        why.append(f"distro '{m.group(0)}' in Server header")
    fz = FROZEN.get(ver)
    if fz and (not fz["requires_hint"] or why):
        why.append(f"{ver} is the version {fz['distro']} ships and patches by backport")
    eol = (maj, mino) < EOL_BELOW
    if why:
        base = "no routine upstream fix for this branch, but " if eol else f"{ver} < upstream fixed {maj}.{mino}.{fixed}, but "
        return "VERIFY_DISTRO_BACKPORT", "low", base + "; ".join(why) + ": the vendor may have backported the fix. Verify on the host."
    if eol:
        return "EOL_NO_UPSTREAM_FIX", "high", f"PHP {ver}: branch below {EOL_BELOW[0]}.{EOL_BELOW[1]} has no routine upstream fix; upgrade or obtain a vendor backport."
    return "LIKELY_VULNERABLE", "high", f"{ver} < fixed {maj}.{mino}.{fixed}."


CMS_MARKERS = [
    ("WordPress", re.compile(r"wp-content|wp-includes|content=\"WordPress", re.I)),
    ("Drupal", re.compile(r"Drupal|/sites/default/files", re.I)),
    ("Joomla", re.compile(r"Joomla!|/media/jui/", re.I)),
    ("Magento", re.compile(r"Magento|/static/version\d+|mage/cookies", re.I)),
    ("Laravel", re.compile(r"laravel_session", re.I)),
    ("phpMyAdmin", re.compile(r"phpMyAdmin|pma_", re.I)),
    ("Nextcloud/ownCloud", re.compile(r"nextcloud|owncloud", re.I)),
    ("MediaWiki", re.compile(r"MediaWiki", re.I)),
    ("Moodle", re.compile(r"MoodleSession", re.I)),
    ("Roundcube", re.compile(r"roundcube", re.I)),
    ("GLPI", re.compile(r"glpi", re.I)),
    ("Zabbix", re.compile(r"zabbix", re.I)),
]


# --deep probes for applications that only run on PHP: a content match proves a PHP runtime even when every header
# is stripped. (path, app, accepted HTTP statuses, body pattern). Status alone never counts (catch-all/SPA servers).
PHP_APPS = [
    ("/wp-login.php", "WordPress", {200}, re.compile(r'name="log"|id="user_login"|wp-submit', re.I)),
    ("/xmlrpc.php", "WordPress", {200, 405}, re.compile(r"XML-RPC server accepts POST requests only", re.I)),
    ("/status.php", "Nextcloud/ownCloud", {200}, re.compile(r'"installed"\s*:\s*(true|false).*"versionstring"', re.I | re.S)),
    ("/phpmyadmin/", "phpMyAdmin", {200}, re.compile(r"<title>[^<]*phpMyAdmin|pma_username|phpmyadmin\.css", re.I)),
    ("/administrator/", "Joomla", {200}, re.compile(r'content="Joomla!|com_login|/media/system/js/', re.I)),
    ("/user/login", "Drupal", {200}, re.compile(r'name="Generator" content="Drupal|drupal-settings-json', re.I)),
]
SELF = "p2s.self.invalid"  # stands in for the scanned host when resolving relative links
PHP_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#?\s]{1,200}\.php)(?:[?#][^"']*)?["']""", re.I)


def harvest_php_links(body, host_names, base="/", limit=3):
    """Same-host .php paths linked from a page at `base` (href/src/action), as absolute paths. Free: no extra request."""
    out = []
    for m in PHP_LINK_RE.finditer(body or ""):
        u = urlparse(urljoin(f"http://{SELF}{base}", m[1]))
        if u.scheme not in ("http", "https") or (u.hostname or "").lower() not in {SELF, *host_names}:
            continue
        p = u.path
        if p not in out:
            out.append(p)
        if len(out) >= limit:
            break
    return out


def detect(responses, probe_paths=(), catch_all=False):
    """responses: list of dicts {path,status,headers,cookies,body}. Returns fingerprint dict.
    catch_all: a random /<x>.php answered 200, so a bare 200 on a .php path proves nothing."""
    versions, indicators, cms = set(), set(), set()
    apps = {p: (name, sts, rx) for p, name, sts, rx in PHP_APPS}
    server = xpb = ""
    http_status = ""
    for i, r in enumerate(responses):
        h = r["headers"]
        if i == 0:
            http_status = r["status"]
        server = server or h.get("server", "")
        xpb = xpb or h.get("x-powered-by", "")
        blob = " ".join([h.get("server", ""), h.get("x-powered-by", ""), h.get("x-generator", "")])
        for m in VER_RE.finditer(blob):  # 'PHP/8.3.36, PHP/8.1.0' (joined duplicates): keep every one
            versions.add((int(m[1]), int(m[2]), int(m[3]), m[4]))
        low = blob.lower()
        if re.search(r"\bphp\b", blob, re.I) or "mod_php" in low:
            indicators.add("header:PHP")
        if "frankenphp" in low:
            indicators.add("server:FrankenPHP")
        if "lsphp" in low:
            indicators.add("server:lsphp")
        for c in r["cookies"]:
            cl = c.lower()
            if cl.startswith("phpsessid="):
                indicators.add("cookie:PHPSESSID")
            if "laravel_session" in cl:
                indicators.add("cookie:laravel_session")
        if r["path"] in probe_paths and r["status"] == 200 and r["path"].endswith(".php") and not catch_all:
            indicators.add("path:" + r["path"])
        if h.get("location") and urlparse(h["location"]).path.lower().endswith(".php"):
            indicators.add("redirect:.php")
        body = r.get("body", "")
        app = apps.get(r["path"]) if r["path"] in probe_paths else None
        if app and r["status"] in app[1] and app[2].search(body):
            indicators.add("app:" + app[0])
            cms.add(app[0])
        for name, rx in CMS_MARKERS:
            if rx.search(body) or any(rx.search(c) for c in r["cookies"]):
                cms.add(name)
    if cms:
        indicators.add("cms")
    return {"versions": sorted(versions), "indicators": sorted(indicators), "cms": sorted(cms),
            "server": server, "x_powered_by": xpb, "http_status": http_status}


def fpm_status(f):
    """(status, confidence, note) for an exposed FastCGI answer (p2s.fcgi.probe)."""
    who = "PHP-FPM" if f["php"] else "a FastCGI server (PHP not confirmed)"
    ver = ""
    if f["php_version"]:
        m = re.match(r"(\d+)\.(\d+)\.(\d+)(.*)", f["php_version"])
        if m:
            ver = f" PHP {f['php_version']}: {status_label(classify_version(int(m[1]), int(m[2]), int(m[3]), m[4])[0])}."
    return ("FPM_EXPOSED", "high" if f["php"] else "medium",
            f"{who} answers FastCGI on this port ({f['evidence']}). Direct remote code execution path.{ver}")


def apply_oracle(status, conf, note, oracle):
    """Combine the banner verdict with an --oracle result. The oracle observes the RUNNING process:
    a pre-fix answer outranks any banner; a fixed answer resolves hidden/distro builds but never overrides a banner
    that discloses a vulnerable upstream version (that is a conflict to review, e.g. another backend behind a proxy)."""
    if not oracle:
        return status, conf, note
    res, where = oracle.get("result"), f"{oracle.get('path', '')}, {oracle.get('markers', 0)}/3 warnings"
    if res == "VULNERABLE":
        was = f" Banner said: {status_label(status)}." if status not in ("PHP_VERSION_HIDDEN", "NO_PHP_INDICATOR") else ""
        return ("ORACLE_VULNERABLE", "high",
                f"Behavioural check ({where}): the running PHP printed the session-write warning that the fix removed.{was}")
    if res == "PATCHED":
        if status in ("LIKELY_VULNERABLE", "EOL_NO_UPSTREAM_FIX"):
            return status, conf, (f"{note} Conflict: behavioural check ({where}) answered like a fixed build; "
                                  "another PHP may serve this request (proxy/backend). Verify on the host.")
        return ("ORACLE_PATCHED", "medium",
                f"Behavioural check ({where}): read warnings shown, session-write warning absent, as in fixed builds.")
    why = {"SILENT": "no PHP warnings displayed (display_errors/display_startup_errors off, upload progress off, "
                     "strict session mode or a non-files handler); not evidence either way",
           "PARTIAL": "incomplete warning set; not evidence either way",
           "UNVALIDATED": f"2/3 warnings from session handler '{oracle.get('handler', '')}', which the lab has not validated; "
                          "not evidence either way"}.get(res, oracle.get("error", "not run"))
    return status, conf, f"{note} Behavioural check: {why}."


def banner_status(fp):
    """(status, confidence, php_version_str, note) from a fingerprint."""
    if fp["versions"]:  # several disclosed versions (proxies, joined headers): the most urgent one decides
        hint = f"{fp['server']} {fp['x_powered_by']}"
        st, conf, note, v = min(((*classify_version(*v, hint=hint), v) for v in fp["versions"]), key=lambda x: rank(x[0]))
        return st, conf, "%d.%d.%d%s" % v, note
    if fp["indicators"]:
        return ("PHP_VERSION_HIDDEN", "low", "",
                "PHP present/likely but the version is not disclosed. Verify on the host; treat as exposed until proven patched.")
    return ("NO_PHP_INDICATOR", "low", "",
            "No PHP indicator in the response. Not proof of absence (reverse proxy / stripped headers).")
