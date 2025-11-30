<?php
// Single-file WHOIS lookup suitable for SiteGround (place in public_html)
// - Supports HTML form with inline AJAX lookup (JSON used internally for inline UI)
// - Validates domain/IP input and prevents CRLF injection
// - Uses port 43 TCP WHOIS lookups and follows simple referrals

declare(strict_types=1);

// Minimal mapping for common TLDs. This can be extended if needed.
$DEFAULT_SERVER = 'whois.iana.org';
$TLD_SERVERS = [
    'com' => 'whois.verisign-grs.com',
    'net' => 'whois.verisign-grs.com',
    'org' => 'whois.pir.org',
    'info' => 'whois.afilias.net',
    'biz' => 'whois.neulevel.biz',
    'io' => 'whois.nic.io',
    'co' => 'whois.nic.co',
    'uk' => 'whois.nic.uk',
    'us' => 'whois.nic.us',
    'ca' => 'whois.cira.ca',
    'de' => 'whois.denic.de',
    'nl' => 'whois.domain-registry.nl',
];

function is_valid_domain_or_ip(string $input): bool
{
    $input = trim($input);
    if ($input === '') return false;

    // disallow newline, CR or control characters to avoid header injection
    if (preg_match('/[\r\n\x00-\x1F]/', $input)) return false;

    // IPv4 or IPv6
    if (filter_var($input, FILTER_VALIDATE_IP)) return true;

    // Simple domain name validation (does not cover every IDN case)
    // Accepts labels with letters, digits, and hyphens, no leading/trailing hyphen, length rules
    if (preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $input)) {
        return true;
    }

    return false;
}

function determine_whois_server(string $name): string
{
    global $TLD_SERVERS, $DEFAULT_SERVER;
    $n = strtolower(trim(preg_replace('#^https?://#i', '', $name)));
    $n = explode('/', $n, 2)[0];

    if (filter_var($n, FILTER_VALIDATE_IP)) {
        return 'whois.arin.net';
    }

    $parts = explode('.', $n);
    $last = array_pop($parts);
    if ($last === null) return $DEFAULT_SERVER;

    // handle co.uk and some 2LDs
    if (count($parts) > 0) {
        $second = end($parts);
        $sld = $second . '.' . $last;
        if (in_array($sld, ['co.uk','org.uk','ac.uk'])) return 'whois.nic.uk';
    }

    return $TLD_SERVERS[$last] ?? $DEFAULT_SERVER;
}

function whois_query(string $server, string $query, int $timeout = 10): string
{
    $query = trim($query);
    $port = 43;

    $fp = @fsockopen($server, $port, $errno, $errstr, $timeout);
    if (! $fp) {
        return ""; // upstream not reachable
    }

    // Some whois servers expect the domain followed by CRLF
    fwrite($fp, $query . "\r\n");
    stream_set_timeout($fp, $timeout);

    $resp = '';
    while (!feof($fp)) {
        $resp .= fgets($fp, 2048);
        // very large responses could cause long read times — optional break or streaming
    }
    fclose($fp);

    return trim($resp);
}

function find_referral(string $whoisText): ?string
{
    $lines = preg_split('/\r?\n/', $whoisText);
    foreach ($lines as $line) {
        if (stripos($line, 'referralserver:') !== false) {
            [$k, $v] = array_map('trim', explode(':', $line, 2) + [null, null]);
            $v = preg_replace('#^whois://#i', '', $v);
            return $v ?: null;
        }
        if (stripos($line, 'whois server:') !== false) {
            [$k, $v] = array_map('trim', explode(':', $line, 2) + [null, null]);
            return $v ?: null;
        }
    }
    return null;
}

// Simple rate limiting: 1 request per 3 seconds per IP using file-based cache (works on shared hosting)
function throttle_ok(string $clientIp, int $limitSec = 3): bool
{
    $dir = sys_get_temp_dir() . '/siteground_whois';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $file = $dir . '/last_' . preg_replace('/[^a-z0-9\-_.]/i', '_', $clientIp);
    $now = time();
    if (file_exists($file)) {
        $last = (int)@file_get_contents($file);
        if ($now - $last < $limitSec) return false;
    }
    @file_put_contents($file, (string)$now);
    return true;
}

// send strict no-cache headers for dynamic responses
function send_no_cache_headers(): void
{
    // HTTP 1.1
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Cache-Control: post-check=0, pre-check=0', false);
    // HTTP 1.0
    header('Pragma: no-cache');
    // Expires in the past
    header('Expires: 0');
}

// handle request
$q = (string)($_REQUEST['q'] ?? '');
// explicit output format removed; inline UI uses AJAX requests for compact responses
$client = $_SERVER['REMOTE_ADDR'] ?? 'cli';

if ($q === '') {
        // show a nice HTML form for manual lookups with right-column ad placeholder
        send_no_cache_headers();
        header('Content-Type: text/html; charset=utf-8');
        ?>
        <!doctype html>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>WHOIS lookup</title>
        <link rel="icon" type="image/png" href="assets/glitchdata_logo1.png">
        <link rel="apple-touch-icon" href="assets/glitchdata_logo1.png">
        <link rel="stylesheet" href="assets/style.css">
        

        <div class="container" id="app" data-theme="">
            <div>
                <div class="topbar">
                                        <div style="display:flex;align-items:center;gap:12px">
                                            <img src="assets/glitchdata_logo1.png" alt="GlitchData" width="36" height="36" style="display:block;outline: none; border: 0">
                                            <h1 style="margin:0">WHOIS lookup</h1>
                                        </div>
                        <div class="dark-toggle card" style="display:flex;gap:8px;padding:8px;align-items:center;">
                        <span class="label-muted">Dark</span>
                        <label class="switch" title="Toggle dark mode">
                            <input id="themeToggle" type="checkbox" aria-label="Toggle dark mode">
                            <span class="slider" aria-hidden="true"></span>
                        </label>
                    </div>
                </div>

                <div class="card">
                    <form method="get" id="whoisForm">
                        <label>
                            <span class="label-muted">Domain or IP</span>
                            <input id="qfield" type="text" name="q" placeholder="example.com or 1.2.3.4">
                        </label>

                        <!-- output format selection removed — UI always uses AJAX for inline lookups -->

                        <div class="actions">
                            <button type="submit">Lookup</button>
                            <button type="button" id="clearBtn" style="background:#e2e8f0;color:var(--fg)">Clear</button>
                            <div style="margin-left:auto;color:var(--muted);font-size:.9rem">Note: Port 43 TCP WHOIS requests may be blocked on some hosts.</div>
                        </div>
                    </form>
                </div>

                <div id="resultWrap" class="card" style="display:none;margin-top:16px">
                    <div style="display:flex;gap:12px;align-items:center">
                        <strong id="titleQuery"></strong>
                        <small id="serverName" class="label-muted"></small>
                        <div style="margin-left:auto;display:flex;gap:8px"><button id="copyBtn" type="button">Copy</button><button id="downloadBtn" type="button">Download</button></div>
                    </div>
                    <hr style="border:0;border-top:1px solid rgba(0,0,0,0.06);margin:12px 0">
                    <pre id="resultPre"></pre>
                </div>

                <footer>
                    <small>Place this file in your SiteGround public_html. Replace ad / analytics placeholders with your IDs.</small>
                </footer>
            </div>

            <aside class="ad">
                <div class="card">
                    <div class="box">

<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-8376419508952050"
     crossorigin="anonymous"></script>
<!-- Skyscraper 300x600 -->
<ins class="adsbygoogle"
     style="display:inline-block;width:300px;height:600px"
     data-ad-client="ca-pub-8376419508952050"
     data-ad-slot="1820822477"></ins>
<script>
     (adsbygoogle = window.adsbygoogle || []).push({});
</script>

                    </div>
                </div>
            </aside>
        </div>

        <script>
            // theme toggling (apply to the whole page)
            const appRoot = document.getElementById('app');
            const root = document.documentElement;
            const toggle = document.getElementById('themeToggle');
            const saved = localStorage.getItem('site_theme');
            if (saved === 'dark') {
                root.setAttribute('data-theme','dark'); toggle.checked = true;
            } else if (saved === null) {
                // respect OS preference when user has not chosen a theme
                const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
                if (prefersDark) { root.setAttribute('data-theme','dark'); toggle.checked = true; }
            }

            toggle.addEventListener('change', () => {
                if (toggle.checked) { root.setAttribute('data-theme','dark'); localStorage.setItem('site_theme','dark'); }
                else { root.removeAttribute('data-theme'); localStorage.setItem('site_theme',''); }
            });

            // client-side helpers
            const form = document.getElementById('whoisForm');
            const qf = document.getElementById('qfield');
            const resultWrap = document.getElementById('resultWrap');
            const titleQuery = document.getElementById('titleQuery');
            const serverName = document.getElementById('serverName');
            const resultPre = document.getElementById('resultPre');
            const copyBtn = document.getElementById('copyBtn');
            const dlBtn = document.getElementById('downloadBtn');

            const showResult = (query, server, text) => {
                titleQuery.textContent = query;
                serverName.textContent = server ? ' — ' + server : '';
                resultPre.textContent = text || '(no response)';
                resultWrap.style.display = 'block';
            };

            copyBtn.addEventListener('click', () => navigator.clipboard.writeText(resultPre.textContent));
            dlBtn.addEventListener('click', () => {
                const blob = new Blob([resultPre.textContent], {type:'text/plain'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = (qf.value || 'whois') + '.txt'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
            });

                form.addEventListener('submit', e => {
                // normal submit will navigate; but for better UX, fetch JSON and show inline
                e.preventDefault();
                const q = qf.value.trim();
                if (!q) return;
                // use ajax=1 (or X-Requested-With header) to request a compact JSON response for the inline UI
                const params = new URLSearchParams(new FormData(form)); params.set('ajax','1');
                fetch('?' + params.toString(), {cache:'no-store', headers: {'X-Requested-With':'XMLHttpRequest'}})
                    .then(r => r.json()).then(obj => {
                    if (obj.error) { showResult(q, '', 'ERROR: ' + (obj.message || '')); }
                    else showResult(q, obj.server || '', obj.result || '(no response)');
                }).catch(err => { showResult(q,'','Lookup failed: ' + err.message); });
            });

            document.getElementById('clearBtn').addEventListener('click', () => { qf.value=''; resultWrap.style.display='none'; });
        </script>

<script async src="https://www.googletagmanager.com/gtag/js?id=G-W3R3LYKS2R"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-W3R3LYKS2R');
</script>

        <?php
        exit;
}

// validate
    // detect AJAX requests (fetch from client-side UI) — default behaviour is HTML
    $is_ajax = (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') || isset($_REQUEST['ajax']);
    if (!is_valid_domain_or_ip($q)) {
    if ($is_ajax) {
            send_no_cache_headers();
            header('Content-Type: application/json; charset=utf-8', true, 400);
        echo json_encode(['error' => 'invalid_query', 'message' => 'Query is not a valid domain or IP']);
    } else {
            send_no_cache_headers();
            header('Content-Type: text/plain; charset=utf-8', true, 400);
        echo "ERROR: Query must be a valid domain name or IP address.\n";
    }
    exit(0);
}

    if (!throttle_ok($client)) {
    if ($is_ajax) {
        send_no_cache_headers();
        header('Content-Type: application/json; charset=utf-8', true, 429);
        echo json_encode(['error' => 'rate_limited', 'message' => 'Rate limit exceeded, try again shortly']);
    } else {
        send_no_cache_headers();
        header('Content-Type: text/plain; charset=utf-8', true, 429);
        echo "ERROR: Rate limit exceeded. Try again later.\n";
    }
    exit(0);
}

$server = determine_whois_server($q);
$result = whois_query($server, $q);

// follow simple referral if present
$ref = find_referral($result);
if ($ref && $ref !== $server) {
    $secondary = whois_query($ref, $q);
    if ($secondary !== '') $result = $secondary;
}

if ($is_ajax) {
    send_no_cache_headers();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['query' => $q, 'server' => $server, 'result' => $result], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// text/html mode — escape output
send_no_cache_headers();
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><meta charset="utf-8"><title>WHOIS result: ' . htmlspecialchars($q, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</title>';
echo '<link rel="icon" type="image/png" href="assets/glitchdata_logo1.png"><link rel="stylesheet" href="assets/style.css">';
echo '<h1>WHOIS: ' . htmlspecialchars($q, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</h1>';
echo '<p><strong>Queried server:</strong> ' . htmlspecialchars($server, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
echo '<pre>' . htmlspecialchars($result === '' ? '(no response)' : $result, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
