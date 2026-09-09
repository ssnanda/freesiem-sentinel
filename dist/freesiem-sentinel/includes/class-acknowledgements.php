<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * "Mark as safe" — a per-site record that an admin has reviewed a finding and
 * decided it is not a threat (a legitimate media upload, a hand-placed tool, a
 * test fixture, ...).
 *
 * Design notes:
 *
 *  - Local only. The record lives in its own wp_option on this site. It is not
 *    controlled by freeSIEM Core; if a snapshot is later pushed to the cloud the
 *    acknowledged findings go with it, tagged, so the backend still sees the
 *    real posture rather than a hidden blind spot.
 *
 *  - Survives "Clear Results". The findings cache is wiped by that action; these
 *    records are a separate option and are kept, which is the whole point.
 *
 *  - Bound to the file's bytes. When a finding points at a file we store its
 *    SHA-256 + size at mark time. The mark is only honoured while the file on
 *    disk still hashes the same. If the file changes or disappears the mark is
 *    void and the finding returns at full severity — so "mark safe" can never
 *    become a permanent whitelisted path for a planted shell.
 *
 *  - Findings with no file (database issues, etc.) stay acknowledged until an
 *    admin removes the mark by hand.
 */
class Freesiem_Acknowledgements
{
	public const OPTION = 'freesiem_sentinel_acknowledgements';

	/** Hard cap so a pathological site cannot bloat wp_options. */
	private const MAX_RECORDS = 500;

	private const MAX_NOTE_LEN = 500;

	/**
	 * May the current user mark findings safe? A site can turn the feature off
	 * entirely with the `freesiem_sentinel_allow_acknowledgements` filter.
	 */
	public static function can_manage(): bool
	{
		return current_user_can('manage_options')
			&& (bool) apply_filters('freesiem_sentinel_allow_acknowledgements', true);
	}

	/**
	 * @return array<string,array<string,mixed>> keyed by finding_key
	 */
	public static function all(): array
	{
		$stored = get_option(self::OPTION, []);

		return is_array($stored) ? array_filter($stored, 'is_array') : [];
	}

	public static function get(string $finding_key): ?array
	{
		$all = self::all();

		return isset($all[$finding_key]) ? $all[$finding_key] : null;
	}

	public static function count(): int
	{
		return count(self::all());
	}

	/**
	 * Record a finding as reviewed-and-safe.
	 *
	 * @return true|WP_Error
	 */
	public static function add(array $finding, string $note, string $user_login, int $user_id)
	{
		$key = (string) ($finding['finding_key'] ?? '');

		if ($key === '') {
			return new WP_Error('freesiem_ack_no_key', __('That finding has no stable key and cannot be marked safe.', 'freesiem-sentinel'));
		}

		$note = trim(wp_strip_all_tags((string) $note));

		if ($note === '') {
			return new WP_Error('freesiem_ack_no_note', __('Add a short note saying why this finding is safe — it is kept with the record.', 'freesiem-sentinel'));
		}

		$evidence = is_array($finding['evidence'] ?? null) ? $finding['evidence'] : [];
		$path = ltrim(str_replace('\\', '/', (string) ($evidence['path'] ?? '')), '/');
		$sha256 = '';
		$size = null;

		if ($path !== '') {
			$resolved = Freesiem_File_Actions::resolve($path);

			if (!is_wp_error($resolved)) {
				$sha256 = (string) @hash_file('sha256', $resolved);
				$size = (int) @filesize($resolved);
			}
		}

		$records = self::all();
		$records[$key] = [
			'finding_key' => $key,
			'title' => (string) ($finding['title'] ?? ''),
			'category' => (string) ($finding['category'] ?? ''),
			'severity' => freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info')),
			'signature_id' => (string) ($evidence['signature_id'] ?? ''),
			'path' => $path,
			'sha256' => $sha256,
			'size' => $size,
			'note' => (string) mb_substr($note, 0, self::MAX_NOTE_LEN),
			'user_id' => $user_id,
			'user_login' => $user_login,
			'at' => freesiem_sentinel_get_iso8601_time(),
			'plugin_version' => defined('FREESIEM_SENTINEL_VERSION') ? FREESIEM_SENTINEL_VERSION : '',
		];

		if (count($records) > self::MAX_RECORDS) {
			uasort($records, static function (array $a, array $b): int {
				return strcmp((string) ($a['at'] ?? ''), (string) ($b['at'] ?? ''));
			});
			$records = array_slice($records, -self::MAX_RECORDS, null, true);
		}

		update_option(self::OPTION, $records, false);

		freesiem_sentinel_log_event(
			'finding_marked_safe',
			sprintf('Marked finding "%s" as safe%s.', (string) ($finding['title'] ?? $key), $path !== '' ? ' (' . $path . ')' : ''),
			$user_login,
			'',
			['finding_key' => $key, 'signature_id' => (string) ($evidence['signature_id'] ?? ''), 'path' => $path, 'sha256' => $sha256, 'note' => $note]
		);

		return true;
	}

	public static function remove(string $finding_key, string $user_login = ''): bool
	{
		$records = self::all();

		if (!isset($records[$finding_key])) {
			return false;
		}

		$removed = $records[$finding_key];
		unset($records[$finding_key]);
		update_option(self::OPTION, $records, false);

		freesiem_sentinel_log_event(
			'finding_unmarked_safe',
			sprintf('Removed the safe mark on "%s".', (string) ($removed['title'] ?? $finding_key)),
			$user_login,
			'',
			['finding_key' => $finding_key, 'path' => (string) ($removed['path'] ?? '')]
		);

		return true;
	}

	public static function clear_all(string $user_login = ''): int
	{
		$count = self::count();

		if ($count === 0) {
			return 0;
		}

		delete_option(self::OPTION);

		freesiem_sentinel_log_event(
			'findings_safe_marks_cleared',
			sprintf('Cleared all %d "marked safe" records.', $count),
			$user_login
		);

		return $count;
	}

	/**
	 * Is this acknowledgement still trustworthy?
	 *
	 * A file-backed mark is valid only while the file's bytes are unchanged. A
	 * mark with no file stays valid until removed by hand.
	 */
	public static function is_valid(array $record): bool
	{
		$path = (string) ($record['path'] ?? '');

		if ($path === '') {
			return true;
		}

		$resolved = Freesiem_File_Actions::resolve($path);

		if (is_wp_error($resolved)) {
			// Gone, replaced by a directory/symlink, or now unreadable — whatever
			// was reviewed is no longer what sits at that path.
			return false;
		}

		$expected = (string) ($record['sha256'] ?? '');

		if ($expected === '') {
			// Could not hash at mark time (protected path we can still read for
			// display, say). Fall back to "valid while the file still exists".
			return true;
		}

		return hash_equals($expected, (string) @hash_file('sha256', $resolved));
	}

	/**
	 * Split a findings list into active vs acknowledged. Pure — never writes.
	 * Acknowledged findings come back with an `acknowledged` sub-array; a finding
	 * whose mark has gone stale is returned in `active` with
	 * `acknowledgement_voided` set so the UI can explain the reappearance.
	 *
	 * @param array<int,mixed> $findings
	 * @return array{active: array<int,array>, acknowledged: array<int,array>}
	 */
	public static function partition(array $findings): array
	{
		$records = self::all();
		$active = [];
		$acknowledged = [];

		foreach ($findings as $finding) {
			if (!is_array($finding)) {
				continue;
			}

			unset($finding['acknowledged'], $finding['acknowledgement_voided']);

			$key = (string) ($finding['finding_key'] ?? '');
			$record = $key !== '' ? ($records[$key] ?? null) : null;

			if ($record === null) {
				$active[] = $finding;
				continue;
			}

			if (self::is_valid($record)) {
				$finding['acknowledged'] = $record;
				$acknowledged[] = $finding;
			} else {
				$finding['acknowledgement_voided'] = true;
				$active[] = $finding;
			}
		}

		return ['active' => $active, 'acknowledged' => $acknowledged];
	}

	/**
	 * Drop records whose file changed or vanished. Called at scan-finalize time
	 * (a write context) so storage does not accumulate dead marks.
	 *
	 * @return int number of records removed
	 */
	public static function prune_stale(): int
	{
		$records = self::all();

		if ($records === []) {
			return 0;
		}

		$keep = [];
		$removed = [];

		foreach ($records as $key => $record) {
			if (self::is_valid($record)) {
				$keep[$key] = $record;
			} else {
				$removed[$key] = $record;
			}
		}

		if ($removed === []) {
			return 0;
		}

		update_option(self::OPTION, $keep, false);

		foreach ($removed as $key => $record) {
			freesiem_sentinel_log_event(
				'finding_safe_mark_voided',
				sprintf('Safe mark on "%s" voided — the file changed or is no longer present.', (string) ($record['title'] ?? $key)),
				'',
				'',
				['finding_key' => $key, 'path' => (string) ($record['path'] ?? '')]
			);
		}

		return count($removed);
	}
}
