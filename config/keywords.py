# =============================================================================
# config/keywords.py
# Chứa toàn bộ hằng số: từ khóa tấn công, extension nguy hiểm, trọng số
# =============================================================================

# --- 1. DANH SÁCH EXTENSION NGUY HIỂM KHI TRUY CẬP TRỰC TIẾP ---
CRITICAL_EXTENSIONS = [
    '.bak', '.old', '.inc', '.nsf', '.tpl', '.cfm', '.cgi',
    '.ini', '.config', '.conf', '.env', '.dat', '.log', '.sql', '.git', '.svn',
    '.sh', '.bin', '.pl', '.py', '.bat', '.cmd', '.mdb', '.sav', '.tmp',
    '.swp', '.lock', '.ds_store', '.java', '.class', '~',
    '.htr', '.exe',  # IIS mapping / executable — 100% attack trong CSIC
]

# --- 2. DANH SÁCH EXTENSION NGUY HIỂM KHI UPLOAD ---
MALICIOUS_UPLOAD_EXTS = [
    '.php', '.php3', '.php4', '.php5', '.phtml', '.exe', '.bin', '.sh', '.bat',
    '.cmd', '.cgi', '.pl', '.jsp', '.asp', '.aspx', '.py', '.dll'
]

# --- 3. TỪ KHÓA SQL INJECTION ---
# Từ ngắn: khớp có ranh giới từ (tránh false positive từ tham số fuzz / từ ghép)
SQLI_BOUNDARY_KEYWORDS = [
    'select', 'union', 'insert', 'delete', 'drop', 'from', 'where', 'having',
]

# Chuỗi / toán tử SQL: khớp substring (không dùng ';' đơn lẻ — trùng Accept;q=...)
SQLI_LITERAL_KEYWORDS = [
    'create table', 'alter table', 'truncate table', '--', '#', '/*', '*/', '%00',
    '1=1', 'or 1=1', 'and 1=1', 'or true', 'or 1=1--', 'version()', 'database()',
    'user()', '@@version', 'sleep(', 'benchmark(', 'delay(', 'waitfor', 'concat(',
    'having', 'char(', 'ascii(', 'substr(', 'substring(',
    'information_schema', 'sysobjects', 'syscolumns',
    'into outfile', 'load_file(', 'xp_', 'sp_',
    'if(', 'mid(', 'length(',
]

# --- 4. TỪ ĐIỂN TỪ KHÓA TẤN CÔNG ---
ATTACK_KEYWORDS = {
    'sqli': SQLI_BOUNDARY_KEYWORDS + SQLI_LITERAL_KEYWORDS,

    'xss': [
        '<script', '</script>', '<img', '<svg', '<body', '<iframe',
        '<object', '<embed',
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onkeydown',
        'javascript:', 'vbscript:', 'vbscript', 'document.cookie',
        'alert(', 'prompt(', 'confirm(',
        'scriptalert', 'crosssitescripting',
        'eval(', 'fromcharcode', 'unescape(',
        '&#x', '%3cscript',
    ],

    'path_traversal': [
        '../', '..\\', '/..', '/..',        # trailing .. để bắt file.bat/..
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        'windows/system32', 'winnt', 'system32',
        'boot.ini', 'win.ini', 'autoexec.bat',
        'file:/', 'c:/windows', 'c:\\windows', 'c:\\winnt',
        'inetpub', 'wwwroot', 'global.asa',
        '%2e%2e%2f', '%2e%2e/',             # URL-encoded ../
        '/proc/self',
    ],

    # Không dùng ';', '|', '&' đơn lẻ: mọi query có & nối tham số sẽ bị tính nhầm
    'cmd_injection': [
        '&&', '||', '`', '$()', '/bin/sh', 'cmd.exe', 'powershell',
        'curl', 'ping', 'whoami', 'cat ', 'grep', 'rm -rf',
        'chmod', 'chown', 'nc -', 'nc -e', 'base64',
        ';ls', '; ls', '/dev/null',
    ],

    'php_injection': [
        'php://input', 'php://filter', 'expect://', 'data://',
        'exec(', 'system(', 'shell_exec(', 'assert(',
        'base64_decode(', 'preg_replace(',
    ],

    'probing': [
        'phpinfo()', 'info.php',
        '/phpmyadmin', '/wp-admin', '/wp-login',
        '/.git/', '/.env', '/.svn/',
        'web-inf', 'web.xml',
        'crossdomain.xml', '/manager/html',
        # IIS / WebSphere / FrontPage / Admin — attack=100% trong CSIC (không xuất hiện trong normal)
        '/_vti_bin', '/_vti_script', '/_vti_pvt', '/_vti_cnf', '/_vti_log',
        '/_cti_pvt', '/_private', '/vti_txt',
        '/iisadmpwd', '/iissamples',
        '/msadc',
        '/webspheresamples', '/exampleswebapp',
        '/samples/', '/samples/isapi', '/samples/dbsamp',
        '/scripts/',
        '/servlet/', '/webapp/',
        '/jstl-war',
        'iisstart',
        '/e2ePortalProject', '/portalappAdmin', '/estore',
        '/ws-client', '/worldmusic',
        '/IBMWebAS', '/travelnet', '/flash/java', '/techniques/',
        '/iisadmin', '/theme', 'databasenotes',
        'mail.box', '.portal',
        '/admin/', '/patient/', '/physican/',
    ],
}

# --- 5. TRỌNG SỐ CHO TỪNG LOẠI TẤN CÔNG ---
WEIGHTS = {
    'sqli':          150,
    'xss':           120,
    'path':          200,
    'cmd':           250,
    'php_injection': 250,
    'probing':       150,
    'invalid_file':  300,
    'manipulation':  150,
    # Trọng số mới
    'empty_probe':   600,   # GET không payload + header scanner → dấu hiệu dò endpoint
    'extra_header':  300,   # mỗi bậc header_anomaly vượt quá 3 → scanner rõ hơn
}

# --- 6. CÁC KÝ TỰ ĐÁNG NGỜ DÙNG ĐỂ FUZZING / INJECTION ---
# Bỏ '-' vì quá phổ biến trong URL, filename, giá trị form bình thường
# → gây 13+ false positive không cần thiết trong manipulate_weight
SUSPICIOUS_CHARS = ['*', '?', '!', "'", '"', '`', '<', '>', ';', '|', '{', '}', '-']

# --- 7. CÁC THAM SỐ PARAMETER TAMPERING ĐIỂN HÌNH ---
TAMPERING_PARAMS = ['cpA=', 'dniA=']

# --- 8. PENALTY URL PATTERNS ---
# Các pattern URL đặc trưng của công cụ quét / exploit
URL_PENALTY_PATTERNS = [
    r'\.jsp/', r'\.gif/', r'\.php/', r'\.html/',
    r'\.jpg/', r'\.css/',          # file-as-directory traversal (175+61 attack, 0 normal)
    r'asf-logo-wide', r'/manager/html', r'tomcat\.css',
    r'/compass', r'logon\.jsp',
    r'\d{10,}\.(jsp|php)',
    r'/\d{10,}',  # path chứa số dài ≥10 digit = SQL injection qua URL path (967 attack, 0 normal)
]

# --- 9. UA CỦA SCANNER / BOT ĐÃ BIẾT ---
# Konqueror xuất hiện trong 1.101 missed attacks của dataset CSIC
# Các tool HTTP/scanner phổ biến khác
SCANNER_UA_PATTERNS = [
    'konqueror',
    'nikto', 'nmap', 'sqlmap', 'masscan', 'zgrab',
    'python-requests', 'python-urllib',
    'go-http-client',
    'libwww-perl',
    'java/',
    'curl/', 'wget/',
    'ruby', 'perl/',
    'scrapy',
    'burpsuite', 'dirbuster', 'gobuster', 'wfuzz',
]

# --- 10. GIÁ TRỊ cache-control HIẾM GẶP Ở BROWSER THẬT ---
# Trình duyệt thực tế hầu như chỉ gửi: no-cache, no-store, max-age=N
# Các giá trị dưới đây chỉ có trong HTTP clients tự động / scanner
SUSPICIOUS_CACHE_VALUES = {
    'no-transform',
    'only-if-cached',
    'max-stale',
    'min-fresh',
}
