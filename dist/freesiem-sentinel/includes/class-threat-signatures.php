<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Curated, built-in malware / web-shell signature set for the local deep scan.
 *
 * Every rule is a self-contained associative array:
 *   - id             stable slug, used in finding keys
 *   - label          short human title
 *   - severity       critical|high|medium|low
 *   - score          finding score (lower is worse, matches Freesiem_Scanner::finding())
 *   - category       finding category bucket (malware|filesystem|...)
 *   - classes        which file classes the rule applies to (php|js|html|htaccess|text|peek|any)
 *   - pattern        PCRE, already delimited. Patterns are written to be linear-time
 *                    (no nested unbounded quantifiers) to avoid catastrophic backtracking.
 *   - recommendation remediation guidance
 *
 * Kept intentionally conservative: rules that overlap with common legitimate code are
 * scored lower / marked medium so the scan stays useful without drowning admins in noise.
 */
class Freesiem_Threat_Signatures
{
	/**
	 * File classes that get a full content read + signature match.
	 */
	private const FULL_EXTENSIONS = [
		'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'phar', 'pht',
		'inc', 'module', 'install', 'tpl',
		'js', 'mjs', 'cjs',
		'html', 'htm', 'xhtml', 'shtml', 'svg',
		'ini', 'json', 'xml', 'txt', 'sql',
		'pl', 'cgi', 'py', 'sh',
	];

	/**
	 * File classes that only get a small header peek (polyglot / injected payload check).
	 */
	private const PEEK_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'ico', 'bmp', 'webp'];

	/**
	 * Common web-shell / recon filenames (lower-cased basenames).
	 */
	private const WEBSHELL_FILENAMES = [
		// Distinctive, effectively-never-legitimate shell / dropper names only.
		// Deliberately excludes generic names (shell.php, sql.php, x.php, cmd.php,
		// up.php, mini.php, idx.php, radio.php, dropdown.php, ...) that turn up in
		// legitimate libraries — Text_Diff ships wp-includes/Text/Diff/Engine/shell.php.
		'c99.php', 'c100.php', 'r57.php', 'wso.php', 'b374k.php', '0byt3m1n1.php',
		'wshell.php', 'minishell.php', 'wp-conflg.php', 'wp-login.php.php', 'upload.php.php',
		'404.php.php', 'marijuana.php', 'indoxploit.php', 'gel4y.php', 'madspot.php',
		'lock360.php', 'alfa-rex.php', 'wsoyanz.php', 'priv8.php', 'k2ll33d.php',
	];

	public static function full_extensions(): array
	{
		return self::FULL_EXTENSIONS;
	}

	public static function peek_extensions(): array
	{
		return self::PEEK_EXTENSIONS;
	}

	/**
	 * Decide how a given file should be scanned.
	 *
	 * @return string one of 'full', 'peek', 'skip'
	 */
	public static function scan_mode(string $basename, string $extension): string
	{
		$basename = strtolower($basename);
		$extension = strtolower($extension);

		if ($basename === '.htaccess' || $basename === '.user.ini' || $basename === 'php.ini' || $basename === '.env') {
			return 'full';
		}

		if (in_array($extension, self::FULL_EXTENSIONS, true)) {
			return 'full';
		}

		if (in_array($extension, self::PEEK_EXTENSIONS, true)) {
			return 'peek';
		}

		return 'skip';
	}

	/**
	 * Classify a file for rule targeting.
	 *
	 * @return string php|js|html|htaccess|text
	 */
	public static function classify(string $basename, string $extension): string
	{
		$basename = strtolower($basename);
		$extension = strtolower($extension);

		if ($basename === '.htaccess' || $basename === '.user.ini' || $basename === 'php.ini') {
			return 'htaccess';
		}

		if (in_array($extension, ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'phar', 'pht', 'inc', 'module', 'install', 'tpl'], true)) {
			return 'php';
		}

		if (in_array($extension, ['js', 'mjs', 'cjs'], true)) {
			return 'js';
		}

		if (in_array($extension, ['html', 'htm', 'xhtml', 'shtml', 'svg'], true)) {
			return 'html';
		}

		return 'text';
	}

	public static function is_webshell_filename(string $basename): bool
	{
		$basename = strtolower(trim($basename));

		if (in_array($basename, self::WEBSHELL_FILENAMES, true)) {
			return true;
		}

		// image extension immediately followed by a script extension: photo.jpg.php
		if (preg_match('/\.(jpe?g|png|gif|bmp|ico|webp|svg)\.(php\d?|phtml|phar|pht|shtml)$/i', $basename)) {
			return true;
		}

		return false;
	}

	/**
	 * Whether a PHP filename looks machine-generated rather than human-named —
	 * the pattern droppers use (hex/base32 blobs, no word structure). Plain
	 * length is NOT a signal: WordPress core ships class-wp-customize-nav-menu-
	 * item-setting.php and dozens like it.
	 */
	public static function looks_random_filename(string $basename): bool
	{
		$name = strtolower((string) preg_replace('/\.(php\d?|phtml|phar|pht|inc)$/i', '', $basename));

		if ($name === '' || strlen($name) < 10) {
			return false;
		}

		// Separators (- _ .) and the word structure they bracket are the mark of
		// a human-chosen name. Only a single unbroken token is a candidate for
		// "machine generated", so anything with a separator is out.
		if (preg_match('/[-_.]/', $name)) {
			return false;
		}

		$len = strlen($name);
		$digits = preg_match_all('/\d/', $name);
		$vowels = preg_match_all('/[aeiou]/', $name);

		// Hex blob: nothing but hex digits, and at least one actual digit. A real
		// name is never a 12+ char run of only a-f (strtolower() already ran, so
		// this must exclude ordinary lowercase words like "installedpackage").
		if ($digits > 0 && preg_match('/^[a-f0-9]{12,}$/', $name)) {
			return true;
		}

		// Base32 blob: 16+ chars confined to the RFC 4648 lowercase alphabet and
		// salted with its 2-7 digits the way encoded output is. Ordinary words
		// also match [a-z2-7]+, so require several bare 2-7 digits AND a vowel
		// share too low to be language.
		if ($len >= 16
			&& preg_match('/^[a-z2-7]+$/', $name)
			&& preg_match_all('/[2-7]/', $name) >= 3
			&& $vowels / $len < 0.3) {
			return true;
		}

		// Keyboard mash / consonant soup: a 10+ char token with no vowels at all
		// ("kjhgtrfvbn"), or one long enough with a vowel share too low to be words.
		if ($vowels === 0 || ($len >= 14 && $vowels / $len < 0.12)) {
			return true;
		}

		// High share of digits in the token ("x8291736451a").
		if ($digits >= 6 && $digits / $len >= 0.4) {
			return true;
		}

		return false;
	}

	/**
	 * Plain-language summary of what a flagged data / script file actually does,
	 * so an admin can judge "database dump" vs "deploy script" vs "reverse shell"
	 * without opening it. $head is the first chunk of the file.
	 *
	 * @return array{summary:string,danger:bool,flags:string[]}
	 */
	public static function describe_data_file(string $head, string $extension, string $basename): array
	{
		$extension = strtolower($extension);
		$basename = strtolower($basename);
		$flags = [];
		$danger = false;

		if (trim($head) === '') {
			return ['summary' => 'Empty file — contains nothing.', 'danger' => false, 'flags' => ['empty']];
		}

		$lines = substr_count($head, "\n") + 1;

		$is_shell = in_array($extension, ['sh', 'bash', 'zsh', 'ksh'], true)
			|| (bool) preg_match('~^#!\s*/\S*/(?:ba|z|k)?sh\b~', $head);
		$is_python = $extension === 'py' || (bool) preg_match('~^#!\s*\S*python~', $head);
		$is_perl = in_array($extension, ['pl', 'cgi'], true) || (bool) preg_match('~^#!\s*\S*perl~', $head);

		if ($is_shell || $is_python || $is_perl) {
			$does = [];

			if (preg_match('~\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b~i', $head)
				|| preg_match('~\b(?:curl|wget)\b[^\n]*\|\s*(?:python|perl|php)\b~i', $head)) {
				$does[] = 'downloads remote content and pipes it straight into an interpreter';
				$danger = true;
				$flags[] = 'remote_exec';
			}

			if (preg_match('~authorized_keys~', $head)) {
				$does[] = 'writes to SSH authorized_keys';
				$danger = true;
				$flags[] = 'ssh_key';
			}

			if (preg_match('~\bcrontab\b|/etc/cron|/var/spool/cron~i', $head)) {
				$does[] = 'installs a cron job';
				$danger = true;
				$flags[] = 'cron';
			}

			if (preg_match('~/dev/tcp/|\bnc(?:at)?\b\s+-\S*l|bash\s+-i\b|sh\s+-i\b|socket\.socket~i', $head)) {
				$does[] = 'opens a network listener or reverse shell';
				$danger = true;
				$flags[] = 'reverse_shell';
			}

			if (preg_match('~\bbase64\b\s+-{0,2}d[^\n]*\|\s*(?:ba)?sh|\beval\b\s*[("`$]|\bexec\s*\(~i', $head)) {
				$does[] = 'decodes and runs an embedded payload';
				$danger = true;
				$flags[] = 'obfuscated_exec';
			}

			if (preg_match('~\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b~i', $head)) {
				$does[] = 'recursively deletes files (rm -rf)';
				$flags[] = 'destructive';
			}

			if (preg_match('~\bchmod\s+(?:[0-7]?7[0-7]{2}\b|\+s\b|[ugo]\+s\b)~', $head)) {
				$does[] = 'loosens file permissions (world-writable or setuid)';
				$flags[] = 'perms';
			}

			if (preg_match('~\b(?:mysqldump|mysql|pg_dump|psql|wp\s+db)\b~i', $head)) {
				$does[] = 'runs database commands';
			}

			if (preg_match('~\bwp\s+(?:plugin|theme|user|option|core|config|cron|search-replace|eval)\b~i', $head)) {
				$does[] = 'runs WP-CLI commands';
			}

			if (preg_match('~\b(?:apt|apt-get|yum|dnf|apk|brew)\s+(?:install|add)\b~i', $head)) {
				$does[] = 'installs system packages';
			}

			if (preg_match('~\bgit\s+(?:clone|pull|fetch|checkout|reset)\b~i', $head)) {
				$does[] = 'runs git operations';
			}

			if (preg_match('~\b(?:rsync|scp|sftp)\b~i', $head)) {
				$does[] = 'transfers files to or from another host';
			}

			$kind = $is_python ? 'Python script' : ($is_perl ? 'Perl / CGI script' : 'Shell script');
			$summary = $does === []
				? sprintf('%s, ~%d line(s). No high-risk operations recognised.', $kind, $lines)
				: sprintf('%s that %s.', $kind, self::join_clauses($does));

			return ['summary' => $summary, 'danger' => $danger, 'flags' => array_values(array_unique($flags))];
		}

		if ($extension === 'sql' || preg_match('~^\s*(?:--|/\*|SET\s|START TRANSACTION|CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE)~i', $head)) {
			$does = [];
			$creates = (int) preg_match_all('~\bCREATE\s+TABLE\b~i', $head);
			$inserts = (int) preg_match_all('~\bINSERT\s+INTO\b~i', $head);
			$drops = (int) preg_match_all('~\bDROP\s+(?:TABLE|DATABASE)\b~i', $head);

			if ($creates > 0) {
				$does[] = sprintf('%d CREATE TABLE', $creates);
			}

			if ($inserts > 0) {
				$does[] = sprintf('%d INSERT', $inserts);
			}

			if ($drops > 0) {
				$does[] = sprintf('%d DROP', $drops);
				$flags[] = 'destructive';
			}

			if (preg_match('~`?\w*users`?[^\n;]{0,80}(?:user_pass|user_login|user_email)~i', $head)
				|| preg_match('~(?:CREATE\s+TABLE|INSERT\s+INTO)\s+`?\w*users`?~i', $head)) {
				$does[] = 'includes a users table (login names and password hashes)';
				$flags[] = 'contains_credentials';
			}

			if (preg_match('~`?\w*options`?[^\n;]{0,80}siteurl~i', $head) || preg_match('~siteurl[^\n;]{0,80}`?\w*options`?~i', $head)) {
				$does[] = 'appears to be a full site database export';
			}

			if (preg_match('~UPDATE\s+`?\w*users`?\s+SET[^\n;]*user_pass~i', $head)) {
				$does[] = 'changes a user password';
				$flags[] = 'contains_credentials';
			}

			$summary = $does === []
				? sprintf('SQL script, ~%d statement line(s).', $lines)
				: sprintf('SQL dump / script: %s.', self::join_clauses($does));

			return ['summary' => $summary, 'danger' => false, 'flags' => array_values(array_unique($flags))];
		}

		if (in_array($extension, ['bak', 'old', 'save', 'orig', 'swp', 'swo'], true) || str_contains($basename, 'wp-config')) {
			if (preg_match('~DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_SALT~', $head)) {
				return [
					'summary' => 'Backup copy of wp-config.php — exposes the database credentials and secret keys if it can be fetched over the web.',
					'danger' => true,
					'flags' => ['contains_credentials'],
				];
			}

			if (preg_match('~<\?php~', $head)) {
				return ['summary' => sprintf('Backup of a PHP file, ~%d line(s).', $lines), 'danger' => false, 'flags' => []];
			}

			return ['summary' => sprintf('Backup / editor temp file, ~%d line(s).', $lines), 'danger' => false, 'flags' => []];
		}

		if (in_array($extension, ['zip', 'gz', 'tgz', 'tar', 'bz2', 'xz', '7z', 'rar'], true)) {
			return [
				'summary' => 'Compressed archive — contents not inspected here. If it is not something you placed, download and examine it offline before deleting.',
				'danger' => false,
				'flags' => ['archive'],
			];
		}

		return ['summary' => sprintf('~%d line(s) of text; no notable operations recognised.', $lines), 'danger' => false, 'flags' => []];
	}

	private static function join_clauses(array $items): string
	{
		$items = array_values(array_filter($items, static fn ($i): bool => $i !== ''));

		if ($items === []) {
			return '';
		}

		if (count($items) === 1) {
			return $items[0];
		}

		$last = array_pop($items);

		return implode(', ', $items) . ' and ' . $last;
	}

	/**
	 * The full rule set. Cached per-request.
	 */
	public static function rules(): array
	{
		static $rules = null;

		if (is_array($rules)) {
			return $rules;
		}

		$rules = [
			// ---- PHP: dynamic execution of attacker-controlled or encoded payloads ----
			[
				'id' => 'php_eval_encoded_payload',
				'label' => 'eval() of an encoded / compressed payload',
				'severity' => 'critical',
				'score' => 20,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:eval|assert)\s*\(\s*(?:\/\*[^*]*\*\/\s*)?(?:\$\w+\s*\(\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|hex2bin|convert_uudecode|pack)\s*\(/i',
				'recommendation' => 'This is a hallmark of injected malware. Isolate the file, compare it against a known-good copy, and remove the malicious code.',
			],
			[
				'id' => 'php_eval_superglobal',
				'label' => 'Code executed directly from request input',
				'severity' => 'critical',
				'score' => 18,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:eval|assert|create_function)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i',
				'recommendation' => 'A remote attacker can run arbitrary PHP through this file. Treat the site as compromised, remove the code, and rotate all credentials.',
			],
			[
				'id' => 'php_dynamic_call_superglobal',
				'label' => 'Function name taken from request input and called',
				'severity' => 'high',
				'score' => 40,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
				'recommendation' => 'This pattern lets a visitor pick which PHP function runs and with what arguments. Remove it unless you can prove it is a deliberate, safe feature.',
			],
			[
				'id' => 'php_shell_exec_superglobal',
				'label' => 'System command built from request input',
				'severity' => 'critical',
				'score' => 20,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:[\'"][^\'"]{0,40}[\'"]\s*\.\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
				'recommendation' => 'This allows operating-system command execution from the browser. Remove it and audit the server for further compromise.',
			],
			[
				'id' => 'php_backtick_superglobal',
				'label' => 'Shell backticks with request input',
				'severity' => 'critical',
				'score' => 22,
				'category' => 'malware',
				'classes' => ['php'],
				// Must be at a statement/expression position (after = ( , => return echo
				// print .). Without that anchor this matches PHPDoc prose that quotes
				// `$_POST['action']` in a code span, which WP core does constantly.
				'pattern' => '/(?:[=(,.]|=>|\breturn|\becho|\bprint)\s*`[^`\n]{1,180}\$_(?:GET|POST|REQUEST|COOKIE)\b[^`\n]{0,120}`/',
				'recommendation' => 'Backtick operators run shell commands. Combined with request input this is remote command execution — remove it immediately.',
			],
			[
				'id' => 'php_preg_replace_eval',
				'label' => 'preg_replace() with the /e code-execution modifier',
				'severity' => 'high',
				'score' => 38,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/preg_replace\s*\(\s*([\'"])(?:(?!\1)[\s\S]){1,200}[\/#~!%|}\]][a-zA-Z]{0,10}e[a-zA-Z]{0,10}\1\s*,/i',
				'recommendation' => 'The /e modifier evaluates the replacement as PHP and is a classic backdoor technique. Replace with preg_replace_callback() or remove.',
			],
			[
				'id' => 'php_create_function',
				'label' => 'create_function() used to build code at runtime',
				'severity' => 'medium',
				'score' => 60,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\bcreate_function\s*\(/i',
				'recommendation' => 'create_function() is removed in PHP 8 and is frequently used to hide malware. Confirm the source and replace with a closure.',
			],
			[
				'id' => 'php_nested_decoders',
				'label' => 'Nested decode / decompress calls',
				'severity' => 'high',
				'score' => 36,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode)\s*\(/i',
				'recommendation' => 'Layered decoding is almost always used to conceal a payload. Decode it in a sandbox to confirm, then remove.',
			],
			[
				'id' => 'php_char_concat_chain',
				'label' => 'Long chr()/ord() concatenation chain',
				'severity' => 'high',
				'score' => 42,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/chr\s*\(\s*\d{1,3}\s*\)(?:\s*\.\s*chr\s*\(\s*\d{1,3}\s*\)){7,}/i',
				'recommendation' => 'Building strings from many chr() calls is an obfuscation technique. Reconstruct the string to see what it does, then remove.',
			],
			[
				'id' => 'php_hex_escape_blob',
				'label' => 'Executable-looking \\x hex-escaped string',
				'severity' => 'low',
				'score' => 82,
				'category' => 'malware',
				'classes' => ['php'],
				// Long hex-escaped strings are also just binary constants (crypto
				// tables in sodium_compat, etc.). Only treat it as suspicious when
				// it is being fed straight into eval/assert/a decoder/a callable.
				'pattern' => '/(?:eval|assert|create_function|call_user_func|base64_decode|gzinflate|preg_replace)\s*\(\s*["\'](?:\\\\x[0-9A-Fa-f]{2}){12,}/i',
				'recommendation' => 'A hex-escaped string passed to eval() or a decoder is an obfuscated payload. Reconstruct it to confirm.',
			],
			[
				'id' => 'php_globals_dynamic_call',
				'label' => 'Call through $GLOBALS[...] indirection',
				'severity' => 'high',
				'score' => 44,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\$GLOBALS\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\(/',
				'recommendation' => 'Indirect calls via $GLOBALS are used to evade scanners. Confirm the referenced value is not attacker-controlled.',
			],
			[
				'id' => 'php_reversed_keywords',
				'label' => 'Reversed PHP keyword (strrev obfuscation)',
				'severity' => 'medium',
				'score' => 55,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(edoced_46esab|etalfnizg|ssergnocnuzg|31_tor_rts|lave|metsys|cexe_llehs|ecalper_gerp)\b/i',
				'recommendation' => 'Reversed function names paired with strrev() hide malicious calls. Remove the code.',
			],
			[
				'id' => 'php_variable_function_from_string',
				'label' => 'Function name stored in a variable then called',
				'severity' => 'medium',
				'score' => 62,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\$\w+\s*=\s*[\'"](?:base64_decode|gzinflate|str_rot13|assert|eval|system|passthru|shell_exec|create_function|call_user_func|file_put_contents)[\'"]\s*;/i',
				'recommendation' => 'Assigning a sensitive function name to a variable is a common evasion trick. Confirm how the variable is later used.',
			],
			[
				'id' => 'php_include_remote',
				'label' => 'include / require of a remote URL',
				'severity' => 'high',
				'score' => 38,
				'category' => 'malware',
				'classes' => ['php'],
				// Require a real host after the scheme AND a matching close quote, so docblock
			// prose (Does not include "http://" or "https://".) is not read as require('http://x').
			'pattern' => '/\b(?:include|include_once|require|require_once)\s*\(?\s*([\'"])https?:\/\/[^\'"\s]{2,}\1/i',
				'recommendation' => 'Remote file inclusion lets an external server dictate what code runs here. Remove it and set allow_url_include=0.',
			],
			[
				'id' => 'php_include_writable_path',
				'label' => 'include / require from an upload or temp path',
				'severity' => 'medium',
				'score' => 55,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:include|include_once|require|require_once)\s*\(?\s*[^;\n]{0,120}(?:\/uploads\/|\/tmp\/|sys_get_temp_dir|wp-content\/cache\/)/i',
				'recommendation' => 'Loading executable code from a writable directory is dangerous. Confirm this file and the included path are legitimate.',
			],
			[
				'id' => 'php_write_executable_file',
				'label' => 'Writes a PHP file to disk',
				'severity' => 'medium',
				'score' => 62,
				'category' => 'malware',
				'classes' => ['php'],
				// Exclude "…/index.php": every plugin writes an empty
				// "<?php // Silence is golden" guard file into its own directories.
				'pattern' => '/\b(?:file_put_contents|fwrite|fputs)\s*\(\s*[^,;\n]{0,140}(?<!index)\.(?:php\d?|phtml|phar|pht)[\'"]\s*,/i',
				'recommendation' => 'Droppers write new PHP files that become backdoors. Verify this behaviour is expected.',
			],
			[
				'id' => 'php_move_uploaded_to_php',
				'label' => 'Moves an uploaded file to a PHP path',
				'severity' => 'high',
				'score' => 40,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/move_uploaded_file\s*\([^;\n]{0,160}\.(?:php\d?|phtml|phar|pht)[\'"]/i',
				'recommendation' => 'Allowing uploads to land as executable PHP is a direct path to a web shell. Restrict upload types and target directory.',
			],
			[
				'id' => 'php_creates_admin_user',
				'label' => 'Creates or elevates an administrator account',
				'severity' => 'high',
				'score' => 44,
				'category' => 'malware',
				'classes' => ['php'],
				// Needs an actual user-creation / role-setting call. A bare
				// "'role' => 'administrator'" array key shows up in capability maps,
				// role editors and test factories all over legitimate code.
				'pattern' => '/(?:wp_insert_user|wp_create_user|wp_update_user)\s*\([^;]{0,300}[\'"]administrator[\'"]|->\s*(?:set_role|add_role)\s*\(\s*[\'"]administrator[\'"]\s*\)/i',
				'recommendation' => 'Backdoors often add a hidden admin. Confirm this code belongs to a trusted plugin/theme and review your user list.',
			],
			[
				'id' => 'php_base64_long_literal',
				'label' => 'Very long base64 string literal',
				'severity' => 'low',
				'score' => 80,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/[\'"][A-Za-z0-9+\/]{320,}={0,2}[\'"]/',
				'recommendation' => 'Large embedded base64 blobs can be fonts or images, but are also how payloads are shipped. Decode it to confirm what it contains.',
			],
			[
				'id' => 'php_suspicious_ini_set',
				'label' => 'Redirects the error log at runtime',
				'severity' => 'low',
				'score' => 85,
				'category' => 'malware',
				'classes' => ['php'],
				// display_errors / log_errors toggling is normal hardening (WP core
				// does it in load.php). The shell tell is nulling the error_log path
				// so its own noise never lands anywhere.
				'pattern' => '/@?ini_set\s*\(\s*[\'"]error_log[\'"]\s*,\s*(?:NULL|[\'"][\'"]|false|0)\s*\)/i',
				'recommendation' => 'Nulling the error_log path is a way for injected code to stay silent. Check the surrounding code.',
			],

			// ---- Known web-shell fingerprints ----
			[
				'id' => 'webshell_known_family',
				'label' => 'Known web-shell fingerprint',
				'severity' => 'critical',
				'score' => 15,
				'category' => 'malware',
				'classes' => ['php', 'text', 'html'],
				'pattern' => '/\b(?:c99shell|c100shell|r57shell|b374k|FilesMan|WSO[ _]?(?:shell|version)|IndoXploit|Sh3ll|MulCiShell|GudanG|k2ll33d|SnIpEr_SA|Casus15|priv8\s*shell|antichat\s*shell|by\s*orb|Symlink\s*Bypass|Mini\s*Shell|AK-74\s*Security|marijuana\s*shell)\b/i',
				'recommendation' => 'This file matches a known web shell. Remove it, then investigate how it was placed and close that entry point.',
			],
			[
				'id' => 'webshell_common_scaffolding',
				'label' => 'Web-shell scaffolding markers',
				'severity' => 'high',
				'score' => 34,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\$(?:auth_pass|default_action|default_use_ajax|color)\s*=\s*[\'"][^\'"]*[\'"]\s*;[^\n]{0,120}(?:FilesMan|SafeMode|md5\s*\(\s*\$_POST)/i',
				'recommendation' => 'These variables are part of common web-shell control panels. Treat the file as malicious.',
			],
			[
				'id' => 'webshell_password_gate',
				'label' => 'Password-gated code execution',
				'severity' => 'high',
				'score' => 36,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/if\s*\(\s*(?:md5|sha1|crypt|hash)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\)\s*(?:={2,3})\s*[\'"][0-9a-f]{16,}[\'"]/i',
				'recommendation' => 'A hashed-password check guarding request handling is typical of a private backdoor. Remove the file.',
			],

			// ---- JavaScript / HTML injection ----
			[
				'id' => 'js_document_write_unescape',
				'label' => 'document.write(unescape(...)) obfuscation',
				'severity' => 'high',
				'score' => 42,
				'category' => 'malware',
				'classes' => ['js', 'html'],
				'pattern' => '/document\s*\.\s*write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(/i',
				'recommendation' => 'This is a common way to inject hidden markup or redirect visitors. Remove the injected script.',
			],
			[
				'id' => 'js_fromcharcode_chain',
				'label' => 'Long String.fromCharCode sequence',
				'severity' => 'high',
				'score' => 44,
				'category' => 'malware',
				'classes' => ['js', 'html'],
				'pattern' => '/String\s*\.\s*fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){14,}\d{1,3}/i',
				'recommendation' => 'Encoding a script as character codes hides its intent. Decode and remove it.',
			],
			[
				'id' => 'js_packer_eval',
				'label' => 'Packed / eval-wrapped JavaScript',
				'severity' => 'medium',
				'score' => 62,
				'category' => 'malware',
				'classes' => ['js', 'html'],
				'pattern' => '/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/i',
				'recommendation' => 'Dean Edwards "packer" output is legitimate in some libraries but also hides injected code. Verify the source of this script.',
			],
			[
				'id' => 'js_crypto_miner',
				'label' => 'In-browser cryptocurrency miner',
				'severity' => 'critical',
				'score' => 24,
				'category' => 'malware',
				'classes' => ['js', 'html', 'php'],
				'pattern' => '/\b(?:coinhive|coin-hive|coinimp|cryptonight|crypto-loot|cryptoloot|webminepool|deepminer|jsecoin|minero\.cc|webmine\.pro)\b/i',
				'recommendation' => 'A miner steals visitor CPU and signals a site compromise. Remove it and audit for the injection point.',
			],
			[
				'id' => 'js_hidden_iframe',
				'label' => 'Hidden / zero-size iframe',
				'severity' => 'medium',
				'score' => 56,
				'category' => 'malware',
				'classes' => ['js', 'html', 'php'],
				// (?<![\w-]) so marginwidth="0" / marginheight="0" on WP core's
				// sandboxed oEmbed iframe (embed.php) don't count as width/height 0.
				'pattern' => '/<iframe[^>]{0,200}(?:(?<![\w-])(?:width|height)\s*=\s*[\'"]?0(?![\d.])|style\s*=\s*[\'"][^\'"]{0,120}(?:display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3}))/i',
				'recommendation' => 'Invisible iframes are used for drive-by downloads and ad fraud. Remove the injected markup.',
			],
			[
				'id' => 'js_external_script_injection',
				'label' => 'External script injected into the DOM',
				'severity' => 'medium',
				'score' => 66,
				'category' => 'malware',
				'classes' => ['js', 'html'],
				// Require a hard-coded external src. document.write('<script src="'+url)
				// with a local variable is a normal lazy-loader (tinymce, polyfills).
				'pattern' => '/(?:innerHTML|insertAdjacentHTML|document\s*\.\s*write)\s*(?:\(|=)[^;\n]{0,40}[\'"]<script[^>]+src\s*=\s*[\\\\\'"]*(?:https?:)?\/\/[a-z0-9.-]/i',
				'recommendation' => 'Loading a script from a hard-coded external host at runtime is a common defacement / redirect technique. Confirm the source.',
			],

			// ---- .htaccess / .user.ini abuse ----
			[
				'id' => 'htaccess_auto_prepend',
				'label' => 'auto_prepend_file / auto_append_file directive',
				'severity' => 'high',
				'score' => 34,
				'category' => 'malware',
				'classes' => ['htaccess'],
				'pattern' => '/(?:php_value|php_admin_value)\s+auto_(?:prepend|append)_file|auto_(?:prepend|append)_file\s*=/i',
				'recommendation' => 'This forces a PHP file to run on every request and is a common persistence mechanism. Confirm the referenced file is trusted.',
			],
			[
				'id' => 'htaccess_addtype_php',
				'label' => 'Non-PHP extension mapped to the PHP handler',
				'severity' => 'critical',
				'score' => 26,
				'category' => 'malware',
				'classes' => ['htaccess'],
				'pattern' => '/(?:AddType|AddHandler)\s+[^\n]{0,60}(?:x-httpd-php|php\d?-script)[^\n]{0,60}\.(?:jpg|jpeg|png|gif|ico|txt|bmp|pdf|zip)\b/i',
				'recommendation' => 'This makes image / text files execute as PHP, hiding a shell in plain sight. Remove the directive.',
			],
			[
				'id' => 'htaccess_sethandler_php',
				'label' => 'SetHandler forces PHP execution',
				'severity' => 'high',
				'score' => 44,
				'category' => 'malware',
				'classes' => ['htaccess'],
				'pattern' => '/SetHandler\s+[^\n]{0,40}(?:x-httpd-php|proxy:fcgi)/i',
				'recommendation' => 'A stray SetHandler in an uploads or content directory usually points at a shell. Verify why it is here.',
			],
			[
				'id' => 'htaccess_malicious_redirect',
				'label' => 'Conditional redirect to an external site',
				'severity' => 'medium',
				'score' => 54,
				'category' => 'malware',
				'classes' => ['htaccess'],
				'pattern' => '/RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]{0,120}\n\s*RewriteRule\s+[^\n]{0,120}https?:\/\//i',
				'recommendation' => 'User-agent / referer gated redirects are used for SEO spam and malvertising. Remove the rules.',
			],

			// ---- Polyglot payloads inside otherwise-binary files ----
			[
				'id' => 'polyglot_php_tag',
				'label' => 'PHP open tag inside an image file',
				'severity' => 'critical',
				'score' => 24,
				'category' => 'malware',
				'classes' => ['peek'],
				'pattern' => '/<\?php[\s\r\n]/i',
				'recommendation' => 'An image that contains PHP code is a disguised shell waiting for a way to execute. Delete it.',
			],
			[
				'id' => 'polyglot_script_tag',
				'label' => 'Script tag inside an image file',
				'severity' => 'high',
				'score' => 44,
				'category' => 'malware',
				'classes' => ['peek'],
				'pattern' => '/<script[\s>]/i',
				'recommendation' => 'Markup embedded in an image is used for stored XSS via content-type sniffing. Remove or re-encode the file.',
			],
		];

		if (function_exists('apply_filters')) {
			$filtered = apply_filters('freesiem_sentinel_threat_signatures', $rules);

			if (is_array($filtered) && $filtered !== []) {
				$rules = $filtered;
			}
		}

		return $rules;
	}

	/**
	 * Return only the rules that apply to a given file class.
	 */
	public static function rules_for_class(string $class): array
	{
		$matches = [];

		foreach (self::rules() as $rule) {
			$classes = isset($rule['classes']) && is_array($rule['classes']) ? $rule['classes'] : ['any'];

			if (in_array('any', $classes, true) || in_array($class, $classes, true)) {
				$matches[] = $rule;
			}
		}

		return $matches;
	}
}
