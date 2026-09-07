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
		'shell.php', 'c99.php', 'c100.php', 'r57.php', 'wso.php', 'b374k.php', 'alfa.php',
		'0byt3m1n1.php', 'cmd.php', 'up.php', 'upload.php.php', 'wshell.php', 'mini.php',
		'minishell.php', 'adminer.php', 'sql.php', 'x.php', 'xx.php', 'xxx.php', 'z.php',
		'404.php.php', 'wp-conflg.php', 'wp-conf.php', 'wp-login.php.php', 'radio.php',
		'marijuana.php', 'indoxploit.php', 'idx.php', 'gel4y.php', 'priv8.php', 'byp.php',
		'bypass.php', 'sym.php', 'symlink.php', 'madspot.php', 'lock360.php', 'dropdown.php',
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
				'pattern' => '/`[^`\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)[^`\n]{0,200}`/',
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
				'label' => 'Long \\x hex-escaped string',
				'severity' => 'medium',
				'score' => 58,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/(?:\\\\x[0-9A-Fa-f]{2}){24,}/',
				'recommendation' => 'Extended hex-escaped strings are used to hide function names and payloads. Verify the intent of this code.',
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
				'pattern' => '/\b(?:include|include_once|require|require_once)\s*\(?\s*[\'"]https?:\/\//i',
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
				'score' => 56,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/\b(?:file_put_contents|fwrite|fputs)\s*\(\s*[^,;\n]{0,140}\.(?:php\d?|phtml|phar|pht)[\'"]\s*[,)]/i',
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
				'score' => 40,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/(?:wp_insert_user|wp_create_user)\s*\([^;]{0,400}[\'"]administrator[\'"]|->\s*set_role\s*\(\s*[\'"]administrator[\'"]\s*\)|[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"]/i',
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
				'label' => 'Disables logging / error output at runtime',
				'severity' => 'low',
				'score' => 82,
				'category' => 'malware',
				'classes' => ['php'],
				'pattern' => '/@?ini_set\s*\(\s*[\'"](?:error_log|log_errors|display_errors)[\'"]\s*,\s*(?:NULL|0|[\'"]0[\'"]|false)\s*\)/i',
				'recommendation' => 'Malware frequently silences logging to stay hidden. Check the surrounding code.',
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
				'pattern' => '/<iframe[^>]{0,200}(?:width\s*=\s*[\'"]?0|height\s*=\s*[\'"]?0|style\s*=\s*[\'"][^\'"]{0,120}(?:display\s*:\s*none|visibility\s*:\s*hidden))/i',
				'recommendation' => 'Invisible iframes are used for drive-by downloads and ad fraud. Remove the injected markup.',
			],
			[
				'id' => 'js_external_script_injection',
				'label' => 'Script written into the DOM from a string',
				'severity' => 'medium',
				'score' => 60,
				'category' => 'malware',
				'classes' => ['js', 'html'],
				'pattern' => '/(?:innerHTML|insertAdjacentHTML|document\s*\.\s*write)\s*[^;\n]{0,60}<script\b/i',
				'recommendation' => 'Injecting <script> tags at runtime is a common defacement / redirect technique. Confirm the source.',
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
