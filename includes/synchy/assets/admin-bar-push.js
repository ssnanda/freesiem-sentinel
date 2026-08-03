(() => {
	"use strict";

	const config = window.synchyAdminBarPushConfig || {};
	const node = document.querySelector("#wp-admin-bar-synchy-site-sync-push");
	const button = node?.querySelector(":scope > .ab-item");

	if (!node || !button) {
		return;
	}

	const setState = (state, label) => {
		node.classList.toggle("synchy-admin-bar-push--disabled", state === "disabled");
		node.classList.toggle("synchy-admin-bar-push--busy", state === "busy");
		button.setAttribute("aria-disabled", state === "disabled" ? "true" : "false");
		button.innerHTML = `<span class="dashicons dashicons-upload" aria-hidden="true"></span>${label}`;
	};

	window.synchySetAdminBarPushEnabled = (enabled) => {
		config.enabled = Boolean(enabled);
		setState(config.enabled ? "enabled" : "disabled", config.pushLabel || "Push");
	};

	const updateStatus = (label, state) => {
		const statusNode = document.querySelector("#wp-admin-bar-synchy-site-sync-status");
		const statusItem = statusNode?.querySelector(":scope > .ab-item");

		if (!statusNode || !statusItem) {
			return;
		}

		statusNode.classList.remove("synchy-admin-bar-status--success", "synchy-admin-bar-status--warning", "synchy-admin-bar-status--error", "synchy-admin-bar-status--running");
		statusNode.classList.add(`synchy-admin-bar-status--${state}`);
		statusItem.innerHTML = `<span class="synchy-admin-bar-status__prefix">Status:</span> ${label}`;
	};

	const sendAjax = async (action, fields = {}) => {
		const body = new FormData();
		body.append("action", action);
		body.append("nonce", config.nonce || "");
		Object.entries(fields).forEach(([key, value]) => body.append(key, value));

		const response = await fetch(config.ajaxUrl, { method: "POST", body, credentials: "same-origin" });
		const payload = await response.json().catch(() => null);

		if (!response.ok || !payload || payload.success !== true) {
			throw new Error(payload?.data?.message || config.unknownError || "Backup & Restore hit an unexpected Sync error.");
		}

		return payload.data || {};
	};

	const finishFullSync = async (job) => {
		let currentJob = job;
		let latestData = {};

		while (currentJob?.runMode === "full" && currentJob?.status === "running") {
			latestData = await sendAjax("synchy_continue_full_sync");
			currentJob = latestData.job || null;
		}

		return latestData;
	};

	const quickPush = async () => {
		if (!config.enabled || node.classList.contains("synchy-admin-bar-push--busy")) {
			return;
		}

		setState("busy", config.preparingLabel || "Preparing...");

		try {
			const runMode = config.requiresBaseline ? "full" : "delta";
			const previewData = await sendAjax("synchy_preview_sync_changes", { synchy_sync_run_mode: runMode });
			const preview = previewData.preview || {};
			const files = Number(preview.filesCount || 0);
			const rows = Number(preview.dbRows || 0);

			if (files === 0 && rows === 0) {
				updateStatus(config.inSyncLabel || "In Sync", "success");
				setState("disabled", config.pushLabel || "Push");
				config.enabled = false;
				window.alert(config.noChangesMessage || "No pending changes were found. The site is in sync.");
				return;
			}

			const isFull = runMode === "full" || Boolean(preview.forceFull);
			const dbEnabled = preview.dbSyncDisabled === false;
			const message = [
				isFull ? (config.confirmFull || "Run a full Sync and send all tracked changes now?") : (config.confirmSync || "Sync the previewed changes to the destination site now?"),
				"",
				`Destination: ${preview.destinationPath || config.destination || "Not set"}`,
				`Files included: ${files.toLocaleString()}`,
				`Database rows: ${rows.toLocaleString()}`,
			].join("\n");

			if (!window.confirm(message)) {
				setState("enabled", config.pushLabel || "Push");
				return;
			}

			setState("busy", config.syncingLabel || "Syncing...");
			updateStatus(config.syncingLabel || "Syncing...", "running");
			const data = await sendAjax("synchy_run_sync_changes", {
				synchy_sync_run_mode: isFull ? "full" : "delta",
				synchy_sync_confirm_db: dbEnabled ? "1" : "",
			});
			const completedData = await finishFullSync(data.job || null);
			const finalStatus = completedData.status || data.status || {};
			if (String(finalStatus.status || "") === "error") {
				throw new Error(finalStatus.message || config.unknownError || "Sync failed.");
			}
			updateStatus(config.inSyncLabel || "In Sync", "success");
			setState("disabled", config.pushLabel || "Push");
			config.enabled = false;
		} catch (error) {
			updateStatus(config.errorLabel || "Sync Error", "error");
			setState("enabled", config.pushLabel || "Push");
			window.alert(error.message);
		}
	};

	setState(config.enabled ? "enabled" : "disabled", config.pushLabel || "Push");
	button.addEventListener("click", (event) => {
		event.preventDefault();
		quickPush();
	});
})();
