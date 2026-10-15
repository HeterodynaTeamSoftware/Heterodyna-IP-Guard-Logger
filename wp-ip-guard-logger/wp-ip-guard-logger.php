<?php
/**
 * Plugin Name: IP Guard Logger (Śledzenie IP i incydentów)
 * Description: Loguje ruch, 404, próby logowania i sygnały ataków. Logi są przechowywane w bazie WordPressa i wyświetlane bezpośrednio w panelu wtyczki.
 * Version: 01.001.0003
 * Author: Heterodyna Team Software
 * Author URI: https://heterodynateamsoftware.pl
 * License: GPLv2 or later
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WPG_IP_Guard_Logger {
    const VERSION = '01.001.0003';
    const DB_VERSION = '2';
    const OPT = 'wpg_ip_guard_logger_opts';
    const DB_OPT = 'wpg_ip_guard_logger_db_version';
    const MIGRATION_OPT = 'wpg_ip_guard_logger_migration_state';
    const COOKIE_SID = 'wpg_ipg_sid';
    const COOKIE_LAST = 'wpg_ipg_last';
    const DEFAULT_SESSION_TTL = 30;
    const MAX_JSON = 16000;
    const PER_PAGE_IPS = 50;
    const PER_PAGE_EVENTS = 100;
    const MIGRATION_BATCH_DIRS = 100;

    private static $inst = null;
    private $req = [];
    private $opts = [];
    private $ips_table = '';
    private $events_table = '';

    public static function instance() {
        if (self::$inst === null) {
            self::$inst = new self();
        }
        return self::$inst;
    }

    private function __construct() {
        global $wpdb;

        $this->ips_table = $wpdb->prefix . 'wpg_ipg_ips';
        $this->events_table = $wpdb->prefix . 'wpg_ipg_events';
        $this->opts = wp_parse_args(get_option(self::OPT, []), $this->defaults());

        $this->maybe_upgrade_db();

        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'admin_init']);

        add_action('init', [$this, 'capture_request_early'], 0);
        add_action('shutdown', [$this, 'capture_request_late'], 0);
        add_action('template_redirect', [$this, 'mark_404'], 0);

        add_action('wp_login_failed', [$this, 'on_login_failed'], 10, 1);
        add_filter('authenticate', [$this, 'on_authenticate'], 30, 3);

        add_action('wpg_ipg_lookup_ip', [$this, 'perform_external_lookup'], 10, 1);
        add_action('wpg_ipg_cleanup', [$this, 'cleanup_old_events']);

        add_action('wp_ajax_wpg_ipg_migrate_legacy', [$this, 'ajax_migrate_legacy']);
    }

    private function defaults() {
        return [
            'enabled' => 1,
            'base_dir' => 'ip-guard-logs',
            'session_ttl_min' => self::DEFAULT_SESSION_TTL,
            'trust_proxy' => 0,
            'trusted_proxy_ips' => '',
            'log_headers' => 1,
            'log_cookies' => 0,
            'external_lookup' => 1,
            'ip_api_endpoint' => 'http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,mobile,query',
            'abuseipdb_key' => '',
            'abuseipdb_days' => 30,
            'suspicious_block_mode' => 0,
            'softblock_threshold' => 8,
            'retention_days' => 0,
        ];
    }

    public static function activate() {
        $inst = self::instance();
        $inst->create_tables();
        $inst->ensure_legacy_base_dir();

        if (!wp_next_scheduled('wpg_ipg_cleanup')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'wpg_ipg_cleanup');
        }
    }

    public static function deactivate() {
        wp_clear_scheduled_hook('wpg_ipg_cleanup');
    }

    private function maybe_upgrade_db() {
        if ((string)get_option(self::DB_OPT, '') !== self::DB_VERSION) {
            $this->create_tables();
        }

        if (!wp_next_scheduled('wpg_ipg_cleanup')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'wpg_ipg_cleanup');
        }
    }

    private function create_tables() {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset = $wpdb->get_charset_collate();

        $sql_ips = "CREATE TABLE {$this->ips_table} (
            ip varchar(45) NOT NULL,
            first_seen datetime DEFAULT NULL,
            last_seen datetime DEFAULT NULL,
            seen_count bigint(20) unsigned NOT NULL DEFAULT 0,
            suspicion_total bigint(20) unsigned NOT NULL DEFAULT 0,
            last_lookup bigint(20) unsigned NOT NULL DEFAULT 0,
            lookup_json longtext NULL,
            abuse_json longtext NULL,
            legacy_imported tinyint(1) NOT NULL DEFAULT 0,
            PRIMARY KEY  (ip),
            KEY last_seen (last_seen),
            KEY suspicion_total (suspicion_total)
        ) $charset;";

        $sql_events = "CREATE TABLE {$this->events_table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ts datetime NOT NULL,
            ip varchar(45) NOT NULL,
            sid varchar(64) NOT NULL DEFAULT '',
            event_type varchar(32) NOT NULL DEFAULT 'request',
            method varchar(10) NOT NULL DEFAULT '',
            status smallint(5) unsigned NOT NULL DEFAULT 0,
            is_404 tinyint(1) NOT NULL DEFAULT 0,
            suspicion smallint(5) unsigned NOT NULL DEFAULT 0,
            path text NULL,
            data_json longtext NULL,
            legacy_key char(64) DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY legacy_key (legacy_key),
            KEY ip_id (ip,id),
            KEY ts (ts),
            KEY event_type (event_type),
            KEY suspicion (suspicion)
        ) $charset;";

        dbDelta($sql_ips);
        dbDelta($sql_events);

        update_option(self::DB_OPT, self::DB_VERSION, false);
    }

    public function admin_menu() {
        add_menu_page(
            'IP Guard Logger',
            'IP Guard Logger',
            'manage_options',
            'wpg-ip-guard-logger',
            [$this, 'render_admin'],
            'dashicons-shield-alt',
            80
        );
    }

    public function admin_init() {
        register_setting('wpg_ipg', self::OPT, [$this, 'sanitize_opts']);
    }

    public function sanitize_opts($in) {
        $d = $this->defaults();
        $out = [];

        foreach ($d as $k => $v) {
            $out[$k] = isset($in[$k]) ? $in[$k] : $v;
        }

        foreach (['enabled', 'trust_proxy', 'log_headers', 'log_cookies', 'external_lookup', 'suspicious_block_mode'] as $key) {
            $out[$key] = (int)!empty($out[$key]);
        }

        $out['base_dir'] = sanitize_file_name($out['base_dir']);
        $out['session_ttl_min'] = max(5, min(240, (int)$out['session_ttl_min']));
        $out['trusted_proxy_ips'] = sanitize_textarea_field($out['trusted_proxy_ips']);
        $out['ip_api_endpoint'] = esc_url_raw($out['ip_api_endpoint']);
        $out['abuseipdb_key'] = sanitize_text_field($out['abuseipdb_key']);
        $out['abuseipdb_days'] = max(1, min(365, (int)$out['abuseipdb_days']));
        $out['softblock_threshold'] = max(1, min(100, (int)$out['softblock_threshold']));
        $out['retention_days'] = max(0, min(3650, (int)$out['retention_days']));

        return $out;
    }

    private function ensure_legacy_base_dir() {
        $up = wp_upload_dir();
        $base = trailingslashit($up['basedir']) . $this->opts['base_dir'];

        if (!file_exists($base)) {
            wp_mkdir_p($base);
        }

        $ht = $base . '/.htaccess';
        if (!file_exists($ht)) {
            @file_put_contents($ht, "Deny from all\n");
        }

        $idx = $base . '/index.html';
        if (!file_exists($idx)) {
            @file_put_contents($idx, "<!-- silence -->");
        }

        return $base;
    }

    private function legacy_base_dir() {
        $up = wp_upload_dir();
        return trailingslashit($up['basedir']) . $this->opts['base_dir'];
    }

    private function is_trusted_proxy($ip) {
        if (!$this->opts['trust_proxy']) {
            return false;
        }

        $list = preg_split('/[\s,]+/', trim((string)$this->opts['trusted_proxy_ips']));
        $list = array_filter($list);
        return in_array($ip, $list, true);
    }

    private function get_client_ip() {
        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        $xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? trim((string)$_SERVER['HTTP_X_FORWARDED_FOR']) : '';
        $xri = isset($_SERVER['HTTP_X_REAL_IP']) ? trim((string)$_SERVER['HTTP_X_REAL_IP']) : '';

        if (!$this->opts['trust_proxy'] || !$this->is_trusted_proxy($remote)) {
            return $this->sanitize_ip($remote);
        }

        $cand = $xri ?: ($xff ? trim(explode(',', $xff)[0]) : $remote);
        return $this->sanitize_ip($cand);
    }

    private function sanitize_ip($ip) {
        $ip = trim((string)$ip);

        if (
            filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
            filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ) {
            return $ip;
        }

        return '0.0.0.0';
    }

    private function is_public_ip($ip) {
        return (bool)filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    private function get_session_id() {
        $ttl = (int)$this->opts['session_ttl_min'];
        $now = time();

        $sid = isset($_COOKIE[self::COOKIE_SID])
            ? preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$_COOKIE[self::COOKIE_SID])
            : '';

        $last = isset($_COOKIE[self::COOKIE_LAST])
            ? (int)$_COOKIE[self::COOKIE_LAST]
            : 0;

        if (!$sid || !$last || (($now - $last) > ($ttl * 60))) {
            $sid = $this->rand_sid();
        }

        if (!headers_sent()) {
            setcookie(self::COOKIE_SID, $sid, $now + ($ttl * 60), COOKIEPATH ?: '/', '', is_ssl(), true);
            setcookie(self::COOKIE_LAST, (string)$now, $now + ($ttl * 60), COOKIEPATH ?: '/', '', is_ssl(), true);
        }

        return $sid;
    }

    private function rand_sid() {
        $bytes = function_exists('random_bytes')
            ? random_bytes(16)
            : openssl_random_pseudo_bytes(16);

        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function request_headers() {
        $headers = [];

        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') !== 0) {
                continue;
            }

            $name = str_replace('_', '-', substr($k, 5));
            $value = is_scalar($v) ? (string)$v : '';

            if (in_array($name, ['AUTHORIZATION', 'COOKIE', 'X-WP-NONCE'], true)) {
                $value = '[REDACTED]';
            }

            $headers[$name] = $value;
        }

        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['CONTENT-TYPE'] = (string)$_SERVER['CONTENT_TYPE'];
        }

        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['CONTENT-LENGTH'] = (string)$_SERVER['CONTENT_LENGTH'];
        }

        return $headers;
    }

    private function safe_cookies() {
        $out = [];

        foreach ($_COOKIE as $name => $value) {
            if (
                stripos($name, 'wordpress_logged_in') !== false ||
                stripos($name, 'wordpress_sec') !== false ||
                stripos($name, 'wp-settings') !== false ||
                stripos($name, 'woocommerce') !== false
            ) {
                $out[$name] = '[REDACTED]';
            } else {
                $out[$name] = is_scalar($value) ? (string)$value : '[NON-SCALAR]';
            }
        }

        return $out;
    }

    private function suspicious_signals($uri, $method) {
        $u = strtolower((string)$uri);
        $score = 0;
        $hits = [];

        $patterns = [
            'wp-login.php' => 2,
            'xmlrpc.php' => 3,
            '/.env' => 5,
            'phpmyadmin' => 5,
            'wp-config' => 5,
            '../' => 4,
            '%2e%2e%2f' => 4,
            'union%20select' => 5,
            'information_schema' => 5,
            'sleep(' => 5,
            'or%201%3d1' => 4,
            'cmd=' => 3,
            'shell' => 3,
            'passwd' => 4,
            'id_rsa' => 4,
            'setup.php' => 2,
            'eval(' => 5,
            'base64_decode' => 5,
        ];

        foreach ($patterns as $pattern => $weight) {
            if (strpos($u, $pattern) !== false) {
                $score += $weight;
                $hits[] = $pattern;
            }
        }

        if ($method === 'POST' && strpos($u, 'wp-login.php') !== false) {
            $score += 1;
            $hits[] = 'POST wp-login';
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT'])
            ? strtolower((string)$_SERVER['HTTP_USER_AGENT'])
            : '';

        if (
            $ua &&
            (
                strpos($ua, 'curl') !== false ||
                strpos($ua, 'wget') !== false ||
                strpos($ua, 'python-requests') !== false
            )
        ) {
            $score += 2;
            $hits[] = 'ua:cli';
        }

        if (!$ua) {
            $score += 1;
            $hits[] = 'ua:empty';
        }

        return [
            'score' => $score,
            'hits' => $hits,
        ];
    }

    private function should_skip_current_request() {
        if (!is_admin()) {
            return false;
        }

        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page === 'wpg-ip-guard-logger') {
            return true;
        }

        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
        return strpos($action, 'wpg_ipg_') === 0;
    }

    private function to_mysql_utc($value = null) {
        $time = $value ? strtotime((string)$value) : time();

        if (!$time) {
            $time = time();
        }

        return gmdate('Y-m-d H:i:s', $time);
    }

    private function trim_json($json) {
        $json = (string)$json;

        if (strlen($json) > self::MAX_JSON) {
            $json = substr($json, 0, self::MAX_JSON) . '...TRUNCATED';
        }

        return $json;
    }

    private function insert_event($entry, $legacy_key = null) {
        global $wpdb;

        $ts = $this->to_mysql_utc(isset($entry['ts']) ? $entry['ts'] : null);
        $ip = $this->sanitize_ip(isset($entry['ip']) ? $entry['ip'] : '0.0.0.0');
        $event_type = isset($entry['event']) && $entry['event']
            ? sanitize_key((string)$entry['event'])
            : 'request';

        $signals = isset($entry['signals']) && is_array($entry['signals'])
            ? $entry['signals']
            : [];

        $suspicion = isset($signals['score'])
            ? max(0, min(65535, (int)$signals['score']))
            : 0;

        $data_json = wp_json_encode(
            $entry,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        $data = [
            'ts' => $ts,
            'ip' => $ip,
            'sid' => isset($entry['sid']) ? substr((string)$entry['sid'], 0, 64) : '',
            'event_type' => substr($event_type ?: 'request', 0, 32),
            'method' => isset($entry['method']) ? substr(strtoupper((string)$entry['method']), 0, 10) : '',
            'status' => isset($entry['status']) ? max(0, min(65535, (int)$entry['status'])) : 0,
            'is_404' => !empty($entry['is_404']) ? 1 : 0,
            'suspicion' => $suspicion,
            'path' => isset($entry['path']) ? (string)$entry['path'] : '',
            'data_json' => $this->trim_json($data_json),
            'legacy_key' => $legacy_key,
        ];

        if ($legacy_key) {
            $sql = $wpdb->prepare(
                "INSERT IGNORE INTO {$this->events_table}
                (ts, ip, sid, event_type, method, status, is_404, suspicion, path, data_json, legacy_key)
                VALUES (%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s)",
                $data['ts'],
                $data['ip'],
                $data['sid'],
                $data['event_type'],
                $data['method'],
                $data['status'],
                $data['is_404'],
                $data['suspicion'],
                $data['path'],
                $data['data_json'],
                $data['legacy_key']
            );

            $wpdb->query($sql);
            return (int)$wpdb->rows_affected;
        }

        $wpdb->insert(
            $this->events_table,
            $data,
            ['%s','%s','%s','%s','%s','%d','%d','%d','%s','%s','%s']
        );

        return (int)$wpdb->insert_id;
    }

    private function update_ip_summary($ip, $ts, $suspicion_delta, $increment_seen = 1) {
        global $wpdb;

        $ip = $this->sanitize_ip($ip);
        $ts = $this->to_mysql_utc($ts);
        $increment_seen = max(0, (int)$increment_seen);
        $suspicion_delta = max(0, (int)$suspicion_delta);

        $sql = $wpdb->prepare(
            "INSERT INTO {$this->ips_table}
            (ip, first_seen, last_seen, seen_count, suspicion_total)
            VALUES (%s,%s,%s,%d,%d)
            ON DUPLICATE KEY UPDATE
                first_seen = CASE
                    WHEN first_seen IS NULL OR first_seen > VALUES(first_seen)
                    THEN VALUES(first_seen) ELSE first_seen END,
                last_seen = CASE
                    WHEN last_seen IS NULL OR last_seen < VALUES(last_seen)
                    THEN VALUES(last_seen) ELSE last_seen END,
                seen_count = seen_count + %d,
                suspicion_total = suspicion_total + %d",
            $ip,
            $ts,
            $ts,
            $increment_seen,
            $suspicion_delta,
            $increment_seen,
            $suspicion_delta
        );

        $wpdb->query($sql);
    }

    private function current_suspicion($ip) {
        global $wpdb;

        $value = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT suspicion_total FROM {$this->ips_table} WHERE ip = %s",
                $ip
            )
        );

        return (int)$value;
    }

    private function queue_external_lookup($ip) {
        global $wpdb;

        if (empty($this->opts['external_lookup']) || !$this->is_public_ip($ip)) {
            return;
        }

        $last_lookup = (int)$wpdb->get_var(
            $wpdb->prepare(
                "SELECT last_lookup FROM {$this->ips_table} WHERE ip = %s",
                $ip
            )
        );

        if ($last_lookup && (time() - $last_lookup) < DAY_IN_SECONDS) {
            return;
        }

        $lock_key = 'wpg_ipg_lookup_' . md5($ip);

        if (get_transient($lock_key)) {
            return;
        }

        set_transient($lock_key, 1, 10 * MINUTE_IN_SECONDS);

        if (!wp_next_scheduled('wpg_ipg_lookup_ip', [$ip])) {
            wp_schedule_single_event(time() + 5, 'wpg_ipg_lookup_ip', [$ip]);
        }
    }

    public function perform_external_lookup($ip) {
        global $wpdb;

        $ip = $this->sanitize_ip($ip);
        $lock_key = 'wpg_ipg_lookup_' . md5($ip);

        if (empty($this->opts['external_lookup']) || !$this->is_public_ip($ip)) {
            delete_transient($lock_key);
            return;
        }

        $lookup = [];
        $abuse = [];

        $tpl = (string)$this->opts['ip_api_endpoint'];

        if ($tpl) {
            $url = str_replace('{ip}', rawurlencode($ip), $tpl);
            $res = wp_remote_get($url, [
                'timeout' => 5,
                'redirection' => 2,
            ]);

            if (!is_wp_error($res)) {
                $j = json_decode((string)wp_remote_retrieve_body($res), true);
                $lookup = is_array($j)
                    ? $j
                    : ['status' => 'fail', 'message' => 'bad_json'];
            } else {
                $lookup = [
                    'status' => 'fail',
                    'message' => $res->get_error_message(),
                ];
            }
        }

        $key = trim((string)$this->opts['abuseipdb_key']);

        if ($key) {
            $days = (int)$this->opts['abuseipdb_days'];
            $url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' .
                rawurlencode($ip) .
                '&maxAgeInDays=' .
                $days .
                '&verbose=true';

            $res = wp_remote_get($url, [
                'timeout' => 8,
                'redirection' => 2,
                'headers' => [
                    'Key' => $key,
                    'Accept' => 'application/json',
                ],
            ]);

            if (!is_wp_error($res)) {
                $j = json_decode((string)wp_remote_retrieve_body($res), true);
                $abuse = is_array($j) ? $j : ['error' => 'bad_json'];
            } else {
                $abuse = ['error' => $res->get_error_message()];
            }
        }

        $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$this->ips_table}
                 SET last_lookup = %d, lookup_json = %s, abuse_json = %s
                 WHERE ip = %s",
                time(),
                wp_json_encode($lookup, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                wp_json_encode($abuse, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                $ip
            )
        );

        delete_transient($lock_key);
    }

    public function capture_request_early() {
        if (empty($this->opts['enabled']) || $this->should_skip_current_request()) {
            return;
        }

        $ip = $this->get_client_ip();
        $sid = $this->get_session_id();
        $method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper((string)$_SERVER['REQUEST_METHOD'])
            : 'GET';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
        $ref = isset($_SERVER['HTTP_REFERER']) ? (string)$_SERVER['HTTP_REFERER'] : '';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
        $host = isset($_SERVER['HTTP_HOST']) ? (string)$_SERVER['HTTP_HOST'] : '';
        $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

        $sig = $this->suspicious_signals($uri, $method);

        $this->req = [
            'ip' => $ip,
            'sid' => $sid,
            'ts' => gmdate('c'),
            'method' => $method,
            'uri' => $uri,
            'host' => $host,
            'proto' => $proto,
            'ref' => $ref,
            'ua' => $ua,
            'sig' => $sig,
            'user_id' => get_current_user_id(),
            'wp_logged_in' => is_user_logged_in() ? 1 : 0,
        ];

        if (!empty($this->opts['suspicious_block_mode'])) {
            $threshold = (int)$this->opts['softblock_threshold'];
            $current = $this->current_suspicion($ip);

            if (($current + (int)$sig['score']) >= $threshold) {
                status_header(429);
                header('Retry-After: 120');
                echo 'Too Many Requests';
                exit;
            }
        }
    }

    public function mark_404() {
        if (empty($this->opts['enabled'])) {
            return;
        }

        if (function_exists('is_404') && is_404()) {
            $this->req['is_404'] = 1;
        }
    }

    public function capture_request_late() {
        if (
            empty($this->opts['enabled']) ||
            empty($this->req) ||
            empty($this->req['ip'])
        ) {
            return;
        }

        $ip = $this->req['ip'];
        $code = function_exists('http_response_code') ? (int)http_response_code() : 0;

        $entry = [
            'ts' => $this->req['ts'],
            'ip' => $ip,
            'sid' => $this->req['sid'],
            'event' => 'request',
            'method' => $this->req['method'],
            'url' => $this->req['proto'] . '://' . $this->req['host'] . $this->req['uri'],
            'path' => $this->req['uri'],
            'status' => $code,
            'ref' => $this->req['ref'],
            'ua' => $this->req['ua'],
            'user_id' => $this->req['user_id'],
            'logged_in' => $this->req['wp_logged_in'],
            'is_404' => !empty($this->req['is_404']) ? 1 : 0,
            'signals' => $this->req['sig'],
        ];

        if (!empty($this->opts['log_headers'])) {
            $entry['headers'] = $this->request_headers();
        }

        if (!empty($this->opts['log_cookies'])) {
            $entry['cookies'] = $this->safe_cookies();
        }

        $this->insert_event($entry);
        $this->update_ip_summary(
            $ip,
            $this->req['ts'],
            (int)$this->req['sig']['score'],
            1
        );
        $this->queue_external_lookup($ip);
    }

    public function on_login_failed($username) {
        if (empty($this->opts['enabled'])) {
            return;
        }

        $ip = $this->get_client_ip();
        $ts = gmdate('c');

        $entry = [
            'ts' => $ts,
            'ip' => $ip,
            'event' => 'login_failed',
            'username' => (string)$username,
            'ua' => isset($_SERVER['HTTP_USER_AGENT'])
                ? (string)$_SERVER['HTTP_USER_AGENT']
                : '',
            'path' => isset($_SERVER['REQUEST_URI'])
                ? (string)$_SERVER['REQUEST_URI']
                : '',
            'signals' => [
                'score' => 3,
                'hits' => ['login_failed'],
            ],
        ];

        $this->insert_event($entry);
        $this->update_ip_summary($ip, $ts, 3, 0);
        $this->queue_external_lookup($ip);
    }

    public function on_authenticate($user, $username, $password) {
        if (empty($this->opts['enabled']) || !is_wp_error($user)) {
            return $user;
        }

        $codes = method_exists($user, 'get_error_codes')
            ? $user->get_error_codes()
            : [];

        if (is_array($codes) && !empty($codes)) {
            $ip = $this->get_client_ip();
            $ts = gmdate('c');

            $entry = [
                'ts' => $ts,
                'ip' => $ip,
                'event' => 'auth_error',
                'codes' => $codes,
                'username' => (string)$username,
                'signals' => [
                    'score' => 1,
                    'hits' => ['auth_error'],
                ],
            ];

            $this->insert_event($entry);
            $this->update_ip_summary($ip, $ts, 1, 0);
            $this->queue_external_lookup($ip);
        }

        return $user;
    }

    public function cleanup_old_events() {
        global $wpdb;

        $days = isset($this->opts['retention_days'])
            ? (int)$this->opts['retention_days']
            : 0;

        if ($days <= 0) {
            return;
        }

        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->events_table} WHERE ts < %s",
                $cutoff
            )
        );
    }

    private function wp_time($mysql_utc) {
        if (!$mysql_utc) {
            return '-';
        }

        return get_date_from_gmt(
            $mysql_utc,
            get_option('date_format') . ' ' . get_option('time_format')
        );
    }

    private function get_dashboard_totals() {
        global $wpdb;

        $row = $wpdb->get_row(
            "SELECT
                COUNT(*) AS ip_count,
                COALESCE(SUM(seen_count),0) AS total_hits,
                COALESCE(SUM(suspicion_total),0) AS suspicion_total
             FROM {$this->ips_table}",
            ARRAY_A
        );

        $last_24h = (int)$wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->events_table}
             WHERE ts >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)"
        );

        return [
            'ip_count' => (int)($row['ip_count'] ?? 0),
            'total_hits' => (int)($row['total_hits'] ?? 0),
            'suspicion_total' => (int)($row['suspicion_total'] ?? 0),
            'last_24h' => $last_24h,
        ];
    }

    private function get_ips_page($search, $page) {
        global $wpdb;

        $page = max(1, (int)$page);
        $offset = ($page - 1) * self::PER_PAGE_IPS;
        $where = '';
        $args = [];

        if ($search !== '') {
            $where = ' WHERE ip LIKE %s';
            $args[] = '%' . $wpdb->esc_like($search) . '%';
        }

        $count_sql = "SELECT COUNT(*) FROM {$this->ips_table}{$where}";
        if ($args) {
            $count_sql = $wpdb->prepare($count_sql, ...$args);
        }

        $total = (int)$wpdb->get_var($count_sql);

        $sql = "SELECT *
                FROM {$this->ips_table}{$where}
                ORDER BY suspicion_total DESC, seen_count DESC, last_seen DESC
                LIMIT %d OFFSET %d";

        $query_args = $args;
        $query_args[] = self::PER_PAGE_IPS;
        $query_args[] = $offset;

        $rows = $wpdb->get_results(
            $wpdb->prepare($sql, ...$query_args),
            ARRAY_A
        );

        return [
            'rows' => is_array($rows) ? $rows : [],
            'total' => $total,
            'pages' => max(1, (int)ceil($total / self::PER_PAGE_IPS)),
            'page' => $page,
        ];
    }

    private function get_events_page($ip, $event_type, $page) {
        global $wpdb;

        $page = max(1, (int)$page);
        $offset = ($page - 1) * self::PER_PAGE_EVENTS;
        $clauses = [];
        $args = [];

        if ($ip !== '') {
            $clauses[] = 'ip = %s';
            $args[] = $ip;
        }

        if ($event_type !== '') {
            $clauses[] = 'event_type = %s';
            $args[] = $event_type;
        }

        $where = $clauses ? ' WHERE ' . implode(' AND ', $clauses) : '';

        $count_sql = "SELECT COUNT(*) FROM {$this->events_table}{$where}";
        if ($args) {
            $count_sql = $wpdb->prepare($count_sql, ...$args);
        }

        $total = (int)$wpdb->get_var($count_sql);

        $sql = "SELECT id,ts,ip,event_type,method,status,is_404,suspicion,path,data_json
                FROM {$this->events_table}{$where}
                ORDER BY id DESC
                LIMIT %d OFFSET %d";

        $query_args = $args;
        $query_args[] = self::PER_PAGE_EVENTS;
        $query_args[] = $offset;

        $rows = $wpdb->get_results(
            $wpdb->prepare($sql, ...$query_args),
            ARRAY_A
        );

        return [
            'rows' => is_array($rows) ? $rows : [],
            'total' => $total,
            'pages' => max(1, (int)ceil($total / self::PER_PAGE_EVENTS)),
            'page' => $page,
        ];
    }

    private function country_asn_from_row($row) {
        $lookup = json_decode((string)($row['lookup_json'] ?? ''), true);
        $abuse = json_decode((string)($row['abuse_json'] ?? ''), true);

        $country = '';
        $asn = '';
        $abuse_score = null;

        if (is_array($lookup)) {
            $country = isset($lookup['countryCode'])
                ? (string)$lookup['countryCode']
                : (isset($lookup['country']) ? (string)$lookup['country'] : '');

            $asn = isset($lookup['as'])
                ? (string)$lookup['as']
                : (isset($lookup['asname']) ? (string)$lookup['asname'] : '');
        }

        if (
            is_array($abuse) &&
            isset($abuse['data']) &&
            is_array($abuse['data']) &&
            isset($abuse['data']['abuseConfidenceScore'])
        ) {
            $abuse_score = (int)$abuse['data']['abuseConfidenceScore'];
        }

        return [$country, $asn, $abuse_score];
    }

    private function render_tabs($active) {
        $tabs = [
            'overview' => 'Przegląd',
            'logs' => 'Logi',
            'settings' => 'Ustawienia',
        ];

        echo '<nav class="nav-tab-wrapper" style="margin-bottom:20px;">';

        foreach ($tabs as $key => $label) {
            $url = admin_url('admin.php?page=wpg-ip-guard-logger&tab=' . $key);
            $class = $active === $key ? ' nav-tab-active' : '';

            echo '<a class="nav-tab' . esc_attr($class) . '" href="' .
                esc_url($url) . '">' .
                esc_html($label) .
                '</a>';
        }

        echo '</nav>';
    }

    private function render_pagination($base_args, $current, $pages) {
        if ($pages <= 1) {
            return;
        }

        $base = add_query_arg($base_args, admin_url('admin.php'));

        echo '<div class="tablenav"><div class="tablenav-pages">';
        echo wp_kses_post(
            paginate_links([
                'base' => add_query_arg('paged', '%#%', $base),
                'format' => '',
                'current' => max(1, (int)$current),
                'total' => max(1, (int)$pages),
                'prev_text' => '‹',
                'next_text' => '›',
            ])
        );
        echo '</div></div>';
    }

    private function has_legacy_logs() {
        $base = $this->legacy_base_dir();

        if (!is_dir($base)) {
            return false;
        }

        $dh = @opendir($base);
        if (!$dh) {
            return false;
        }

        while (($name = readdir($dh)) !== false) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            if (is_dir($base . '/' . $name) && file_exists($base . '/' . $name . '/ip-meta.json')) {
                closedir($dh);
                return true;
            }
        }

        closedir($dh);
        return false;
    }

    public function render_admin() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $tab = isset($_GET['tab'])
            ? sanitize_key(wp_unslash($_GET['tab']))
            : 'overview';

        if (!in_array($tab, ['overview', 'logs', 'settings'], true)) {
            $tab = 'overview';
        }

        echo '<div class="wrap">';
        echo '<h1>IP Guard Logger <span style="font-size:13px;color:#646970;">v' .
            esc_html(self::VERSION) .
            '</span></h1>';

        $this->render_tabs($tab);

        if ($tab === 'logs') {
            $this->render_logs_tab();
        } elseif ($tab === 'settings') {
            $this->render_settings_tab();
        } else {
            $this->render_overview_tab();
        }

        echo '</div>';
    }

    private function render_overview_tab() {
        $totals = $this->get_dashboard_totals();
        $search = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
        $page = isset($_GET['paged']) ? max(1, (int)$_GET['paged']) : 1;
        $data = $this->get_ips_page($search, $page);
        $migration = get_option(self::MIGRATION_OPT, []);
        $legacy = $this->has_legacy_logs();
        ?>
        <style>
            .wpg-cards{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px;margin:12px 0 18px}
            .wpg-card{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:12px}
            .wpg-card strong{display:block;font-size:21px;line-height:1.2;margin-top:3px}
            .wpg-muted{color:#646970}
            .wpg-score-high{font-weight:700;color:#b32d2e}
            .wpg-score-mid{font-weight:700;color:#996800}

            .wpg-compact-table{
                width:100%;
                table-layout:fixed;
                border-collapse:collapse;
            }
            .wpg-compact-table th,
            .wpg-compact-table td{
                padding:6px 7px;
                vertical-align:top;
                line-height:1.28;
                font-size:12px;
                overflow-wrap:anywhere;
                word-break:break-word;
            }
            .wpg-compact-table th{
                white-space:normal;
            }
            .wpg-compact-table code{
                font-size:11px;
                padding:1px 3px;
                white-space:normal;
                overflow-wrap:anywhere;
            }
            .wpg-event-path{
                display:block;
                margin-top:3px;
                max-width:100%;
                line-height:1.25;
                overflow-wrap:anywhere;
                word-break:break-word;
            }
            .wpg-badge{
                display:inline-block;
                padding:1px 5px;
                margin:0 3px 2px 0;
                border:1px solid #c3c4c7;
                border-radius:10px;
                background:#f6f7f7;
                font-size:10px;
                line-height:1.5;
                white-space:nowrap;
            }
            .wpg-log-details details{
                max-width:100%;
            }
            .wpg-log-details summary{
                cursor:pointer;
                white-space:nowrap;
            }
            .wpg-log-details pre{
                width:100%;
                max-width:100%;
                max-height:360px;
                box-sizing:border-box;
                overflow:auto;
                white-space:pre-wrap;
                overflow-wrap:anywhere;
                word-break:break-word;
                background:#f6f7f7;
                padding:8px;
                margin:6px 0 0;
                font-size:11px;
                line-height:1.3;
            }

            .wpg-col-ip{width:12%}
            .wpg-col-first{width:14%}
            .wpg-col-last{width:14%}
            .wpg-col-count{width:8%}
            .wpg-col-score{width:9%}
            .wpg-col-country{width:19%}
            .wpg-col-abuse{width:9%}
            .wpg-col-action{width:15%}

            .wpg-log-time{width:13%}
            .wpg-log-ip{width:12%}
            .wpg-log-type{width:11%}
            .wpg-log-request{width:43%}
            .wpg-log-score{width:8%}
            .wpg-log-details-col{width:13%}

            @media(max-width:1100px){
                .wpg-compact-table th,
                .wpg-compact-table td{font-size:11px;padding:5px}
                .wpg-col-country{width:16%}
                .wpg-log-request{width:39%}
                .wpg-log-details-col{width:17%}
            }
            @media(max-width:900px){
                .wpg-cards{grid-template-columns:repeat(2,1fr)}
            }
        </style>

        <div class="wpg-cards">
            <div class="wpg-card">Adresy IP<strong><?php echo number_format_i18n($totals['ip_count']); ?></strong></div>
            <div class="wpg-card">Łącznie wejść<strong><?php echo number_format_i18n($totals['total_hits']); ?></strong></div>
            <div class="wpg-card">Zdarzenia 24h<strong><?php echo number_format_i18n($totals['last_24h']); ?></strong></div>
            <div class="wpg-card">Suma podejrzaności<strong><?php echo number_format_i18n($totals['suspicion_total']); ?></strong></div>
        </div>

        <?php if ($legacy && empty($migration['done'])) : ?>
            <div class="notice notice-info">
                <p>
                    <strong>Wykryto stare logi plikowe.</strong>
                    Nowa wersja zapisuje logi w bazie WordPressa i wyświetla je bezpośrednio w panelu.
                    Możesz jednorazowo zaimportować stare katalogi bez blokowania strony.
                </p>
                <p>
                    <button type="button" class="button button-primary" id="wpg-start-migration">
                        Importuj stare logi do bazy
                    </button>
                    <span id="wpg-migration-status" style="margin-left:10px;"></span>
                </p>
            </div>
            <script>
            document.addEventListener('DOMContentLoaded', function () {
                const button = document.getElementById('wpg-start-migration');
                const status = document.getElementById('wpg-migration-status');
                if (!button) return;

                button.addEventListener('click', function () {
                    button.disabled = true;
                    status.textContent = 'Start importu...';

                    const run = function () {
                        const body = new URLSearchParams();
                        body.set('action', 'wpg_ipg_migrate_legacy');
                        body.set('_ajax_nonce', '<?php echo esc_js(wp_create_nonce('wpg_ipg_migrate_legacy')); ?>');

                        fetch(ajaxurl, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                            body: body.toString()
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (!data.success) {
                                throw new Error(data.data && data.data.message ? data.data.message : 'Błąd importu');
                            }

                            const d = data.data;
                            status.textContent =
                                'Foldery: ' + d.processed + '/' + d.total +
                                ', zaimportowane zdarzenia: ' + d.events;

                            if (d.done) {
                                status.textContent += ' — gotowe. Odświeżam...';
                                setTimeout(() => location.reload(), 700);
                            } else {
                                setTimeout(run, 100);
                            }
                        })
                        .catch(err => {
                            button.disabled = false;
                            status.textContent = 'Błąd: ' + err.message;
                        });
                    };

                    run();
                });
            });
            </script>
        <?php elseif (!empty($migration['done'])) : ?>
            <div class="notice notice-success is-dismissible">
                <p>
                    Stare logi zostały zaimportowane do bazy.
                    Nowe zdarzenia nie są już zapisywane w osobnych folderach IP.
                </p>
            </div>
        <?php endif; ?>

        <form method="get" style="margin:16px 0;">
            <input type="hidden" name="page" value="wpg-ip-guard-logger">
            <input type="hidden" name="tab" value="overview">
            <p class="search-box" style="float:none;">
                <label class="screen-reader-text" for="wpg-search-ip">Szukaj IP</label>
                <input type="search" id="wpg-search-ip" name="s" value="<?php echo esc_attr($search); ?>" placeholder="np. 20.226.106.38">
                <input type="submit" class="button" value="Szukaj IP">
            </p>
        </form>

        <p>
            <strong>Wyników:</strong> <?php echo number_format_i18n($data['total']); ?>.
            Tabela jest stronicowana — panel nie skanuje już tysięcy katalogów przy każdym wejściu.
        </p>

        <table class="widefat striped wpg-compact-table">
            <colgroup>
                <col class="wpg-col-ip">
                <col class="wpg-col-first">
                <col class="wpg-col-last">
                <col class="wpg-col-count">
                <col class="wpg-col-score">
                <col class="wpg-col-country">
                <col class="wpg-col-abuse">
                <col class="wpg-col-action">
            </colgroup>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Pierwszy raz</th>
                    <th>Ostatni raz</th>
                    <th>Wejścia</th>
                    <th>Podejrz.</th>
                    <th>Kraj / ASN</th>
                    <th>Abuse</th>
                    <th>Logi</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!$data['rows']) : ?>
                <tr><td colspan="8">Brak danych.</td></tr>
            <?php endif; ?>

            <?php foreach ($data['rows'] as $row) : ?>
                <?php
                [$country, $asn, $abuse_score] = $this->country_asn_from_row($row);
                $score = (int)$row['suspicion_total'];
                $score_class = $score >= 50 ? 'wpg-score-high' : ($score >= 10 ? 'wpg-score-mid' : '');
                $logs_url = add_query_arg([
                    'page' => 'wpg-ip-guard-logger',
                    'tab' => 'logs',
                    'ip' => $row['ip'],
                ], admin_url('admin.php'));
                ?>
                <tr>
                    <td><code><?php echo esc_html($row['ip']); ?></code></td>
                    <td><?php echo esc_html($this->wp_time($row['first_seen'])); ?></td>
                    <td><?php echo esc_html($this->wp_time($row['last_seen'])); ?></td>
                    <td><?php echo number_format_i18n((int)$row['seen_count']); ?></td>
                    <td class="<?php echo esc_attr($score_class); ?>"><?php echo number_format_i18n($score); ?></td>
                    <td>
                        <?php echo esc_html($country ?: '-'); ?>
                        <?php if ($asn) : ?><br><small><?php echo esc_html($asn); ?></small><?php endif; ?>
                    </td>
                    <td><?php echo $abuse_score === null ? '-' : esc_html($abuse_score . '%'); ?></td>
                    <td><a class="button" href="<?php echo esc_url($logs_url); ?>">Pokaż logi</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <?php
        $this->render_pagination(
            [
                'page' => 'wpg-ip-guard-logger',
                'tab' => 'overview',
                's' => $search,
            ],
            $data['page'],
            $data['pages']
        );
    }

    private function render_logs_tab() {
        $ip = isset($_GET['ip']) ? $this->sanitize_ip(wp_unslash($_GET['ip'])) : '';
        if ($ip === '0.0.0.0' && (!isset($_GET['ip']) || trim((string)$_GET['ip']) !== '0.0.0.0')) {
            $ip = '';
        }

        $event_type = isset($_GET['event_type'])
            ? sanitize_key(wp_unslash($_GET['event_type']))
            : '';

        $page = isset($_GET['paged']) ? max(1, (int)$_GET['paged']) : 1;
        $data = $this->get_events_page($ip, $event_type, $page);
        ?>
        <h2>Logi zdarzeń</h2>

        <form method="get" style="margin:14px 0 18px;">
            <input type="hidden" name="page" value="wpg-ip-guard-logger">
            <input type="hidden" name="tab" value="logs">

            <label>
                IP:
                <input type="text" name="ip" value="<?php echo esc_attr($ip); ?>" placeholder="wszystkie">
            </label>

            <label style="margin-left:12px;">
                Typ:
                <select name="event_type">
                    <option value="">Wszystkie</option>
                    <option value="request" <?php selected($event_type, 'request'); ?>>request</option>
                    <option value="login_failed" <?php selected($event_type, 'login_failed'); ?>>login_failed</option>
                    <option value="auth_error" <?php selected($event_type, 'auth_error'); ?>>auth_error</option>
                    <option value="legacy_raw" <?php selected($event_type, 'legacy_raw'); ?>>legacy_raw</option>
                </select>
            </label>

            <button class="button">Filtruj</button>

            <?php if ($ip || $event_type) : ?>
                <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=wpg-ip-guard-logger&tab=logs')); ?>">Wyczyść</a>
            <?php endif; ?>
        </form>

        <p>
            <strong>Zdarzeń:</strong> <?php echo number_format_i18n($data['total']); ?>.
            Wyświetlane jest maksymalnie <?php echo (int)self::PER_PAGE_EVENTS; ?> rekordów na stronę.
        </p>

        <table class="widefat striped wpg-compact-table">
            <colgroup>
                <col class="wpg-log-time">
                <col class="wpg-log-ip">
                <col class="wpg-log-type">
                <col class="wpg-log-request">
                <col class="wpg-log-score">
                <col class="wpg-log-details-col">
            </colgroup>
            <thead>
                <tr>
                    <th>Czas</th>
                    <th>IP</th>
                    <th>Typ</th>
                    <th>Żądanie</th>
                    <th>Podejrz.</th>
                    <th>Szczegóły</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!$data['rows']) : ?>
                <tr><td colspan="6">Brak logów dla wybranego filtra.</td></tr>
            <?php endif; ?>

            <?php foreach ($data['rows'] as $row) : ?>
                <?php
                $decoded = json_decode((string)$row['data_json'], true);
                $pretty = is_array($decoded)
                    ? wp_json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    : (string)$row['data_json'];

                $score = (int)$row['suspicion'];
                $score_class = $score >= 5 ? 'wpg-score-high' : ($score > 0 ? 'wpg-score-mid' : '');

                $path = (string)($row['path'] ?: '-');
                $display_path = function_exists('mb_strimwidth')
                    ? mb_strimwidth($path, 0, 90, '…', 'UTF-8')
                    : (strlen($path) > 90 ? substr($path, 0, 87) . '...' : $path);
                ?>
                <tr>
                    <td><?php echo esc_html($this->wp_time($row['ts'])); ?></td>
                    <td><code><?php echo esc_html($row['ip']); ?></code></td>
                    <td><?php echo esc_html($row['event_type']); ?></td>
                    <td>
                        <?php if (!empty($row['method'])) : ?>
                            <span class="wpg-badge"><?php echo esc_html($row['method']); ?></span>
                        <?php endif; ?>

                        <?php if (!empty($row['status'])) : ?>
                            <span class="wpg-badge">HTTP <?php echo (int)$row['status']; ?></span>
                        <?php endif; ?>

                        <?php if (!empty($row['is_404'])) : ?>
                            <span class="wpg-badge">404</span>
                        <?php endif; ?>

                        <code class="wpg-event-path" title="<?php echo esc_attr($path); ?>"><?php echo esc_html($display_path); ?></code>
                    </td>
                    <td class="<?php echo esc_attr($score_class); ?>"><?php echo (int)$score; ?></td>
                    <td class="wpg-log-details">
                        <details>
                            <summary>Pokaż</summary>
                            <pre><?php echo esc_html($pretty); ?></pre>
                        </details>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <?php
        $this->render_pagination(
            [
                'page' => 'wpg-ip-guard-logger',
                'tab' => 'logs',
                'ip' => $ip,
                'event_type' => $event_type,
            ],
            $data['page'],
            $data['pages']
        );
    }

    private function render_settings_tab() {
        $o = $this->opts;
        ?>
        <h2>Ustawienia</h2>

        <p>
            Nowe logi są zapisywane w tabelach bazy WordPressa.
            Pole folderu poniżej służy już tylko do jednorazowego importu logów ze starej wersji.
        </p>

        <form method="post" action="options.php">
            <?php settings_fields('wpg_ipg'); ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">Włączone</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[enabled]" value="1" <?php checked(!empty($o['enabled'])); ?>>
                            Loguj ruch
                        </label>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Folder starych logów</th>
                    <td>
                        <input type="text" class="regular-text" name="<?php echo esc_attr(self::OPT); ?>[base_dir]" value="<?php echo esc_attr($o['base_dir']); ?>">
                        <p class="description">Używany tylko do importu danych ze starej wersji.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">TTL sesji (min)</th>
                    <td>
                        <input type="number" min="5" max="240" name="<?php echo esc_attr(self::OPT); ?>[session_ttl_min]" value="<?php echo esc_attr($o['session_ttl_min']); ?>">
                    </td>
                </tr>

                <tr>
                    <th scope="row">Zaufaj proxy (X-Forwarded-For)</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[trust_proxy]" value="1" <?php checked(!empty($o['trust_proxy'])); ?>>
                            Tak — tylko dla IP wpisanych jako zaufane proxy
                        </label>
                        <p class="description">Nie włączaj bez wskazania zaufanych proxy, bo klient może próbować podszyć się przez X-Forwarded-For.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Zaufane IP proxy</th>
                    <td>
                        <textarea name="<?php echo esc_attr(self::OPT); ?>[trusted_proxy_ips]" rows="4" class="large-text code" placeholder="np. 203.0.113.10, 203.0.113.11"><?php echo esc_textarea($o['trusted_proxy_ips']); ?></textarea>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Loguj nagłówki</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[log_headers]" value="1" <?php checked(!empty($o['log_headers'])); ?>>
                            Tak
                        </label>
                        <p class="description">Wrażliwe nagłówki, np. Authorization i X-WP-Nonce, są maskowane.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Loguj cookies</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[log_cookies]" value="1" <?php checked(!empty($o['log_cookies'])); ?>>
                            Tak
                        </label>
                        <p class="description">Wrażliwe cookies WordPress/WooCommerce są maskowane.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Wzbogacaj IP</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[external_lookup]" value="1" <?php checked(!empty($o['external_lookup'])); ?>>
                            Tak
                        </label>
                        <p class="description">Zapytania ip-api / AbuseIPDB są teraz wykonywane asynchronicznie przez WP-Cron, więc nie opóźniają normalnego wejścia na stronę.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Endpoint ip-api</th>
                    <td>
                        <input type="text" class="large-text" name="<?php echo esc_attr(self::OPT); ?>[ip_api_endpoint]" value="<?php echo esc_attr($o['ip_api_endpoint']); ?>">
                    </td>
                </tr>

                <tr>
                    <th scope="row">AbuseIPDB API key</th>
                    <td>
                        <input type="password" class="regular-text" name="<?php echo esc_attr(self::OPT); ?>[abuseipdb_key]" value="<?php echo esc_attr($o['abuseipdb_key']); ?>" autocomplete="new-password">
                    </td>
                </tr>

                <tr>
                    <th scope="row">AbuseIPDB maxAgeInDays</th>
                    <td>
                        <input type="number" min="1" max="365" name="<?php echo esc_attr(self::OPT); ?>[abuseipdb_days]" value="<?php echo esc_attr($o['abuseipdb_days']); ?>">
                    </td>
                </tr>

                <tr>
                    <th scope="row">Soft-block</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[suspicious_block_mode]" value="1" <?php checked(!empty($o['suspicious_block_mode'])); ?>>
                            Włącz HTTP 429 dla wysokiej podejrzaności
                        </label>
                        <p>
                            Próg:
                            <input type="number" min="1" max="100" name="<?php echo esc_attr(self::OPT); ?>[softblock_threshold]" value="<?php echo esc_attr($o['softblock_threshold']); ?>">
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Retencja logów</th>
                    <td>
                        <input type="number" min="0" max="3650" name="<?php echo esc_attr(self::OPT); ?>[retention_days]" value="<?php echo esc_attr($o['retention_days']); ?>"> dni
                        <p class="description">0 = bez automatycznego usuwania. Czyszczenie dotyczy tabeli zdarzeń, nie podsumowań IP.</p>
                    </td>
                </tr>
            </table>

            <?php submit_button('Zapisz ustawienia'); ?>
        </form>

        <hr>
        <p>
            <strong>RODO/GDPR:</strong>
            wtyczka rejestruje adresy IP i zachowanie użytkowników. Ustal odpowiednią retencję i uwzględnij przetwarzanie tych danych w polityce prywatności.
        </p>
        <?php
    }

    public function ajax_migrate_legacy() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Brak uprawnień.'], 403);
        }

        check_ajax_referer('wpg_ipg_migrate_legacy');

        $base = $this->legacy_base_dir();

        if (!is_dir($base)) {
            update_option(self::MIGRATION_OPT, [
                'done' => 1,
                'processed' => 0,
                'events' => 0,
                'total' => 0,
                'cursor' => '',
            ], false);

            wp_send_json_success([
                'done' => true,
                'processed' => 0,
                'events' => 0,
                'total' => 0,
            ]);
        }

        $all = @scandir($base);
        if (!is_array($all)) {
            wp_send_json_error(['message' => 'Nie można odczytać katalogu starych logów.'], 500);
        }

        $dirs = [];

        foreach ($all as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $dir = $base . '/' . $name;
            if (is_dir($dir) && file_exists($dir . '/ip-meta.json')) {
                $dirs[] = $name;
            }
        }

        sort($dirs, SORT_STRING);

        $state = get_option(self::MIGRATION_OPT, []);
        $cursor = isset($state['cursor']) ? (string)$state['cursor'] : '';
        $processed_total = isset($state['processed']) ? (int)$state['processed'] : 0;
        $events_total = isset($state['events']) ? (int)$state['events'] : 0;
        $start = 0;

        if ($cursor !== '') {
            foreach ($dirs as $idx => $name) {
                if (strcmp($name, $cursor) > 0) {
                    $start = $idx;
                    break;
                }

                $start = $idx + 1;
            }
        }

        $batch = array_slice($dirs, $start, self::MIGRATION_BATCH_DIRS);
        $events_added = 0;
        $processed_now = 0;
        $last_name = $cursor;

        foreach ($batch as $name) {
            $last_name = $name;
            $dir = $base . '/' . $name;
            $meta_file = $dir . '/ip-meta.json';
            $raw_meta = @file_get_contents($meta_file);
            $meta = json_decode((string)$raw_meta, true);

            if (!is_array($meta) || empty($meta['ip'])) {
                $processed_now++;
                continue;
            }

            $ip = $this->sanitize_ip($meta['ip']);

            if ($this->legacy_already_imported($ip)) {
                $processed_now++;
                continue;
            }

            $log_file = $dir . '/combined.log';

            if (is_file($log_file) && ($fh = @fopen($log_file, 'rb'))) {
                while (($line = fgets($fh)) !== false) {
                    $line = trim($line);

                    if ($line === '') {
                        continue;
                    }

                    $entry = json_decode($line, true);

                    if (!is_array($entry)) {
                        $entry = [
                            'ts' => isset($meta['last_seen']) ? $meta['last_seen'] : gmdate('c'),
                            'ip' => $ip,
                            'event' => 'legacy_raw',
                            'path' => '',
                            'signals' => ['score' => 0, 'hits' => []],
                            'raw' => $line,
                        ];
                    }

                    if (empty($entry['ip'])) {
                        $entry['ip'] = $ip;
                    }

                    $legacy_key = hash('sha256', $ip . "\n" . $line);
                    $events_added += $this->insert_event($entry, $legacy_key) ? 1 : 0;
                }

                fclose($fh);
            }

            $this->merge_legacy_meta($ip, $meta);
            $processed_now++;
        }

        $processed_total += $processed_now;
        $events_total += $events_added;
        $done = ($start + count($batch)) >= count($dirs);

        $new_state = [
            'done' => $done ? 1 : 0,
            'processed' => min($processed_total, count($dirs)),
            'events' => $events_total,
            'total' => count($dirs),
            'cursor' => $last_name,
        ];

        update_option(self::MIGRATION_OPT, $new_state, false);

        wp_send_json_success([
            'done' => (bool)$done,
            'processed' => $new_state['processed'],
            'events' => $new_state['events'],
            'total' => $new_state['total'],
        ]);
    }

    private function legacy_already_imported($ip) {
        global $wpdb;

        return (int)$wpdb->get_var(
            $wpdb->prepare(
                "SELECT legacy_imported FROM {$this->ips_table} WHERE ip = %s",
                $ip
            )
        ) === 1;
    }

    private function merge_legacy_meta($ip, $meta) {
        global $wpdb;

        $first = !empty($meta['first_seen'])
            ? $this->to_mysql_utc($meta['first_seen'])
            : gmdate('Y-m-d H:i:s');

        $last = !empty($meta['last_seen'])
            ? $this->to_mysql_utc($meta['last_seen'])
            : $first;

        $seen = max(0, (int)($meta['seen_count'] ?? 0));
        $suspicion = max(0, (int)($meta['suspicion_total'] ?? 0));
        $last_lookup = max(0, (int)($meta['last_lookup'] ?? 0));
        $lookup_json = wp_json_encode(
            isset($meta['lookup']) && is_array($meta['lookup']) ? $meta['lookup'] : [],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        $abuse_json = wp_json_encode(
            isset($meta['abuseipdb']) && is_array($meta['abuseipdb']) ? $meta['abuseipdb'] : [],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        $sql = $wpdb->prepare(
            "INSERT INTO {$this->ips_table}
            (ip,first_seen,last_seen,seen_count,suspicion_total,last_lookup,lookup_json,abuse_json,legacy_imported)
            VALUES (%s,%s,%s,%d,%d,%d,%s,%s,1)
            ON DUPLICATE KEY UPDATE
                first_seen = CASE
                    WHEN first_seen IS NULL OR first_seen > VALUES(first_seen)
                    THEN VALUES(first_seen) ELSE first_seen END,
                last_seen = CASE
                    WHEN last_seen IS NULL OR last_seen < VALUES(last_seen)
                    THEN VALUES(last_seen) ELSE last_seen END,
                seen_count = seen_count + VALUES(seen_count),
                suspicion_total = suspicion_total + VALUES(suspicion_total),
                last_lookup = GREATEST(last_lookup, VALUES(last_lookup)),
                lookup_json = CASE
                    WHEN lookup_json IS NULL OR lookup_json = '' OR lookup_json = '[]'
                    THEN VALUES(lookup_json) ELSE lookup_json END,
                abuse_json = CASE
                    WHEN abuse_json IS NULL OR abuse_json = '' OR abuse_json = '[]'
                    THEN VALUES(abuse_json) ELSE abuse_json END,
                legacy_imported = 1",
            $ip,
            $first,
            $last,
            $seen,
            $suspicion,
            $last_lookup,
            $lookup_json,
            $abuse_json
        );

        $wpdb->query($sql);
    }
}

register_activation_hook(__FILE__, ['WPG_IP_Guard_Logger', 'activate']);
register_deactivation_hook(__FILE__, ['WPG_IP_Guard_Logger', 'deactivate']);

add_action('plugins_loaded', function () {
    WPG_IP_Guard_Logger::instance();
});
