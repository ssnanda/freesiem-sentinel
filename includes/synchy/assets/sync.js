(function () {
	const config = window.synchySyncConfig;

	if (!config) {
		return;
	}

	const form = document.querySelector("[data-synchy-sync-form]");
	const saveButton = document.querySelector("[data-synchy-save-sync]");
	const testButton = document.querySelector("[data-synchy-test-sync]");
	const previewButton = document.querySelector("[data-synchy-preview-sync]");
	const runButton = document.querySelector("[data-synchy-run-sync]");
	const fullSyncButton = document.querySelector("[data-synchy-run-full-sync]");
	const pauseSyncButton = document.querySelector("[data-synchy-pause-sync]");
	const resumeSyncButton = document.querySelector("[data-synchy-resume-sync]");
	const manualBaselineButton = document.querySelector("[data-synchy-mark-baseline]");
	const destinationUrlInput = document.querySelector("[data-synchy-sync-url]");
	const usernameInput = document.querySelector("[data-synchy-sync-username]");
	const passwordInput = document.querySelector("[data-synchy-sync-password]");
	const verifySslInput = document.querySelector("[data-synchy-sync-verify-ssl]");
	const inlineConnectionStatus = document.querySelector("[data-synchy-sync-inline-status]");
	const progress = document.querySelector("[data-synchy-sync-progress]");
	const progressBar = document.querySelector("[data-synchy-sync-progress-bar]");
	const progressPhase = document.querySelector("[data-synchy-sync-progress-phase]");
	const progressPercent = document.querySelector("[data-synchy-sync-progress-percent]");
	const progressMessage = document.querySelector("[data-synchy-sync-progress-message]");
	const progressDetail = document.querySelector("[data-synchy-sync-progress-detail]");
	const stages = document.querySelector("[data-synchy-sync-stages]");
	const connectionPanel = document.querySelector("[data-synchy-sync-connection-result]");
	const connectionBadge = document.querySelector("[data-synchy-sync-connection-badge]");
	const connectionMessage = document.querySelector("[data-synchy-sync-connection-message]");
	const connectionMeta = document.querySelector("[data-synchy-sync-connection-meta]");
	const updateRemoteButton = document.querySelector("[data-synchy-update-remote-synchy]");
	const updateRemoteNote = document.querySelector("[data-synchy-update-remote-note]");
	const previewBadge = document.querySelector("[data-synchy-sync-preview-badge]");
	const previewMessage = document.querySelector("[data-synchy-sync-preview-message]");
	const previewBatchCounter = document.querySelector("[data-synchy-sync-batch-counter]");
	const previewTreeContainer = document.querySelector("[data-synchy-sync-preview-tree]");
	const statusBadge = document.querySelector("[data-synchy-sync-status-badge]");
	const statusSummary = document.querySelector("[data-synchy-sync-status-summary]");
	const targetNote = document.querySelector("[data-synchy-sync-target-note]");
	const scopeInputs = Array.from(document.querySelectorAll("[data-synchy-sync-scope]"));

	if (
		!form ||
		!testButton ||
		!previewButton ||
		!runButton ||
		!fullSyncButton ||
		!pauseSyncButton ||
		!resumeSyncButton ||
		!manualBaselineButton ||
		!saveButton ||
		!destinationUrlInput ||
		!usernameInput ||
		!passwordInput ||
		!previewBadge ||
		!previewMessage ||
		!previewBatchCounter ||
		!statusBadge ||
		!statusSummary
	) {
		return;
	}

	let latestPreview = null;
	let latestPreviewMode = "delta";
	let busy = false;
	let pendingBaselineScopeIds = new Set((config.scopeStatus?.pendingBaselineScopeIds || []).map(String));
	let changedScopeIds = new Set();
	let currentJob = config.currentJob || null;
	let currentConnectionState = config.connectionState || null;
	let autoConnectionCheckStarted = false;
	// Require a live connection test in the current page session before trusting the destination.
	let connectionVerified = false;
	const initialConnectionState = {
		destinationUrl: destinationUrlInput.value.trim(),
		username: usernameInput.value.trim(),
		verifySsl: verifySslInput?.checked ? "1" : "0",
	};

	const escapeHtml = (value) =>
		String(value)
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/"/g, "&quot;")
			.replace(/'/g, "&#039;");

	const formatDateTime = (value) => {
		if (value === null || value === undefined || value === "") {
			return config.strings.never || "Never";
		}

		let date = null;

		if (typeof value === "number") {
			date = new Date(value * 1000);
		} else if (/^\d+$/.test(String(value))) {
			date = new Date(Number(value) * 1000);
		} else {
			date = new Date(String(value));
		}

		return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
	};

	const formatDuration = (seconds) => {
		const numeric = Number(seconds || 0);

		if (!Number.isFinite(numeric) || numeric <= 0) {
			return config.strings.na || "N/A";
		}

		const rounded = Math.max(1, Math.round(numeric));
		const hours = Math.floor(rounded / 3600);
		const minutes = Math.floor((rounded % 3600) / 60);
		const secs = rounded % 60;

		if (hours > 0) {
			return `${hours}h ${minutes}m`;
		}

		if (minutes > 0) {
			return `${minutes}m ${secs}s`;
		}

		return `${secs}s`;
	};

	const formatBytes = (bytes) => {
		const numeric = Number(bytes || 0);

		if (!Number.isFinite(numeric) || numeric <= 0) {
			return "0 B";
		}

		const units = ["B", "KB", "MB", "GB"];
		let value = numeric;
		let unitIndex = 0;

		while (value >= 1024 && unitIndex < units.length - 1) {
			value /= 1024;
			unitIndex += 1;
		}

		return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
	};

	const compareVersions = (left, right) => {
		const normalize = (value) =>
			String(value || "")
				.replace(/^[^0-9]*/, "")
				.split(".")
				.map((part) => Number.parseInt(part, 10) || 0);

		const leftParts = normalize(left);
		const rightParts = normalize(right);
		const length = Math.max(leftParts.length, rightParts.length);

		for (let index = 0; index < length; index += 1) {
			const leftPart = leftParts[index] || 0;
			const rightPart = rightParts[index] || 0;

			if (leftPart === rightPart) {
				continue;
			}

			return leftPart > rightPart ? 1 : -1;
		}

		return 0;
	};

	const refreshRemoteVersionUntilCurrent = (attempt = 0) => {
		const maxAttempts = 6;
		const localVersion = String(config.localPluginVersion || "");
		const remoteVersion = String(currentConnectionState?.remoteSite?.pluginVersion || "");

		if (
			localVersion !== ""
			&& remoteVersion !== ""
			&& compareVersions(remoteVersion, localVersion) >= 0
		) {
			updateRemoteUpdateControls();
			return;
		}

		if (attempt >= maxAttempts) {
			updateRemoteUpdateControls();
			return;
		}

		window.setTimeout(async () => {
			try {
				await performConnectionTest();
			} catch (error) {
				// Keep retrying briefly in case the destination is still reloading the plugin.
			}

			refreshRemoteVersionUntilCurrent(attempt + 1);
		}, attempt === 0 ? 1500 : 2000);
	};

	const renderMeta = (container, items) => {
		if (!container) {
			return;
		}

		const filtered = items.filter((item) => item && item.value !== undefined && item.value !== null && item.value !== "");

		if (filtered.length === 0) {
			container.innerHTML = "";
			return;
		}

		container.innerHTML = filtered
			.map(
				(item) =>
					`<div><span class="synchy-export-meta__label">${escapeHtml(item.label)}</span><strong>${item.html ? item.value : escapeHtml(item.value)}</strong></div>`
			)
			.join("");
	};

	const renderPreviewBatchCounter = (preview) => {
		if (!previewBatchCounter) {
			return;
		}

		const batches = Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
			? currentJob.batches
			: Array.isArray(preview?.batches) ? preview.batches : [];
		const totalBatchesSource = currentJob?.totalBatches ?? preview?.totalBatches ?? batches.length ?? 0;
		const totalBatches = Number(totalBatchesSource);

		if (totalBatches <= 0) {
			previewBatchCounter.textContent = "";
			previewBatchCounter.classList.add("is-hidden");
			return;
		}

		const completedBatchesSource = currentJob?.completedBatches ?? batches.filter((batch) => String(batch?.status || "") === "complete").length ?? 0;
		const completedBatches = Number(completedBatchesSource);

		previewBatchCounter.textContent = `${completedBatches.toLocaleString()} / ${totalBatches.toLocaleString()} ${config.strings.batchesComplete || "batches complete"}`;
		previewBatchCounter.classList.remove("is-hidden");
	};

	const getFileBucketLabel = (scopeId, path) => {
		const normalized = String(path || "").replace(/^\/+/, "");
		const segments = normalized.split("/").filter(Boolean);

		if (segments.length === 0) {
			return config.strings.other || "Other";
		}

		if (scopeId === "files_plugins") {
			return segments[1] || segments[0];
		}

		if (scopeId === "files_themes") {
			return segments[1] || segments[0];
		}

		if (scopeId === "files_uploads") {
			return segments[1] || segments[0];
		}

		return segments[0];
	};

	const buildFileBuckets = (scopeId, files) => {
		const buckets = new Map();

		files.forEach((file) => {
			const path = String(file?.path || "");
			const size = Number(file?.size || 0);
			const bucketLabel = getFileBucketLabel(scopeId, path);

			if (!buckets.has(bucketLabel)) {
				buckets.set(bucketLabel, {
					label: bucketLabel,
					count: 0,
					bytes: 0,
					files: [],
				});
			}

			const bucket = buckets.get(bucketLabel);
			bucket.count += 1;
			bucket.bytes += size;
			bucket.files.push({ path, size });
		});

		return Array.from(buckets.values()).sort((left, right) => left.label.localeCompare(right.label));
	};

	const renderStages = (job) => {
		if (!stages) {
			return;
		}

		const items = Array.isArray(job?.stages) ? job.stages : Array.isArray(config.defaultStages) ? config.defaultStages : [];

		stages.innerHTML = items
			.map(
				(stage) => `
					<div class="synchy-export-stage is-${escapeHtml(stage.state || "pending")}">
						<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
						<div class="synchy-export-stage__content">
							<strong>${escapeHtml(stage.label || "")}</strong>
						</div>
					</div>
				`
			)
			.join("");
	};

	const renderProgress = (job) => {
		if (!progress) {
			renderStages(job);
			return;
		}

		if (!job || !job.status) {
			progress.classList.add("is-hidden");
			renderStages(null);
			return;
		}

		progress.classList.remove("is-hidden");

		if (progressBar) {
			progressBar.style.width = `${job.progress || 0}%`;
		}

		if (progressPhase) {
			progressPhase.textContent = job.phaseLabel || (config.strings.syncRunning || "Sync running");
		}

		if (progressPercent) {
			progressPercent.textContent = `${job.progress || 0}%`;
		}

		if (progressMessage) {
			progressMessage.textContent = job.message || "";
		}

		if (progressDetail) {
			if (job?.runMode === "full" && Number(job.totalBatches || 0) > 0) {
				progressDetail.textContent = `${config.strings.batches || "Batches"}: ${Number(job.completedBatches || 0).toLocaleString()} / ${Number(job.totalBatches || 0).toLocaleString()}${job.currentBatchLabel ? ` | ${config.strings.currentBatch || "Current batch"}: ${job.currentBatchLabel}` : ""}`;
			} else {
				progressDetail.textContent = `${config.strings.selectedChanges || "Selected changes"}: ${Number(job.filesCount || 0).toLocaleString()} files, ${Number(job.dbRows || 0).toLocaleString()} DB rows`;
			}
		}

		renderPreviewBatchCounter(latestPreview);
		renderStages(job);
	};

	const getSelectedScopeIds = () =>
		scopeInputs
			.filter((input) => String(input.value || "") === "1")
			.map((input) => String(input.dataset.scopeId || ""));

	const getSelectedScopeLabels = () =>
		getSelectedScopeIds()
			.map((scopeId) => document.querySelector(`[data-synchy-sync-scope-row][data-scope-id="${scopeId}"] strong`)?.textContent?.trim() || "")
			.filter(Boolean);

	const getHasSelection = () => getSelectedScopeIds().length > 0;

	const getPreviewSelectionInputs = () => Array.from(form.querySelectorAll("[data-synchy-preview-selection]"));

	const getHasSelectedPreviewItems = () => {
		if (latestPreviewMode === "full" || Array.isArray(latestPreview?.batches)) {
			return getHasPreviewChanges();
		}

		const inputs = getPreviewSelectionInputs().filter((input) => input.type === "checkbox");

		if (inputs.length === 0) {
			return false;
		}

		return inputs.some((input) => input.checked);
	};

	const getHasPreviewChanges = () =>
		latestPreview !== null
		&& ((Number(latestPreview.filesCount || 0) > 0) || (Number(latestPreview.dbRows || 0) > 0));

	const getHasPendingBaselineSelection = () =>
		getSelectedScopeIds().some((scopeId) => pendingBaselineScopeIds.has(String(scopeId)));

	const getIsRunningFullSync = () => currentJob?.runMode === "full" && currentJob?.status === "running";
	const getHasResumableFullSync = () =>
		currentJob?.runMode === "full" && ["paused", "failed_partial"].includes(String(currentJob?.status || ""));

	const getRunActionLabel = () =>
		latestPreviewMode === "full" || Boolean(latestPreview?.forceFull)
			? (config.strings.fullSync || "Full Sync")
			:
		getHasPendingBaselineSelection()
			? (config.strings.startBaseline || "Start Baseline")
			: (config.strings.pushChanges || "Push Changes");

	const updateTargetNote = () => {
		if (!targetNote) {
			return;
		}

		const destination = destinationUrlInput?.value?.trim() || "the destination URL above";
		targetNote.textContent = `Sync sends changes only to ${destination}.`;
	};

	const getSelectedScopeIdSet = () => new Set(getSelectedScopeIds().map(String));

	const updateScopeRows = () => {
		scopeInputs.forEach((input) => {
			const row = document.querySelector(`[data-synchy-sync-scope-row][data-scope-id="${String(input.dataset.scopeId || "")}"]`);
			const status = row?.querySelector("[data-synchy-sync-scope-status]");
			const scopeId = String(input.dataset.scopeId || "");
			const pending = pendingBaselineScopeIds.has(scopeId);
			const changed = changedScopeIds.has(scopeId);

			if (!row || !status) {
				return;
			}

			row.classList.toggle("is-pending", pending);
			row.classList.toggle("is-complete", !pending && !changed);
			row.classList.toggle("is-changed", !pending && changed);
			status.classList.remove("synchy-badge--muted", "synchy-badge--warning", "synchy-badge--connected");

			if (pending) {
				status.textContent = config.strings.needsBaseline || "Needs baseline";
				status.classList.add("synchy-badge--warning");
				return;
			}

			if (changed) {
				status.textContent = config.strings.pendingChanges || "Pending changes";
				status.classList.add("synchy-badge--warning");
				return;
			}

			status.textContent = latestPreview
				? (config.strings.noChangesInScope || "No changes")
				: (config.strings.readyForPreview || "Ready for preview");
			status.classList.add("synchy-badge--muted");
		});
	};

	const hasSavedPassword = () => passwordInput.dataset.hasSavedPassword === "1";

	const getConnectionDirty = () =>
		destinationUrlInput.value.trim() !== initialConnectionState.destinationUrl
		|| usernameInput.value.trim() !== initialConnectionState.username
		|| (verifySslInput?.checked ? "1" : "0") !== initialConnectionState.verifySsl
		|| passwordInput.value.trim() !== "";

	const hasConnectionCoreValues = () =>
		destinationUrlInput.value.trim() !== ""
		&& usernameInput.value.trim() !== ""
		&& (passwordInput.value.trim() !== "" || hasSavedPassword());

	const hasConfirmedConnection = () =>
		!getConnectionDirty()
		&& connectionVerified;

	const updateConnectionControls = () => {
		const dirty = getConnectionDirty();

		saveButton.disabled = busy || !dirty;
		testButton.disabled = busy || !hasConnectionCoreValues() || hasConfirmedConnection();

		if (!inlineConnectionStatus) {
			return;
		}

		inlineConnectionStatus.classList.remove("synchy-badge--muted", "synchy-badge--warning", "synchy-badge--connected");

		if (hasConfirmedConnection()) {
			inlineConnectionStatus.textContent = config.strings.connected || "Connected";
			inlineConnectionStatus.classList.add("synchy-badge--connected");
			return;
		}

		if (!dirty && currentConnectionState?.status === "error" && hasConnectionCoreValues()) {
			inlineConnectionStatus.textContent = config.strings.failed || "Failed";
			inlineConnectionStatus.classList.add("synchy-badge--warning");
			return;
		}

		if (dirty && hasConnectionCoreValues()) {
			inlineConnectionStatus.textContent = config.strings.needsRetest || "Needs retest";
			inlineConnectionStatus.classList.add("synchy-badge--warning");
			return;
		}

		inlineConnectionStatus.textContent = hasConnectionCoreValues()
			? (config.strings.notChecked || "Not checked")
			: (config.strings.incomplete || "Incomplete");
		inlineConnectionStatus.classList.add("synchy-badge--muted");
	};

	const updateActionButtons = () => {
		const hasSelection = getHasSelection();
		const runLabel = getRunActionLabel();
		const hasPreviewChanges = getHasPreviewChanges();
		const hasSelectedPreviewItems = getHasSelectedPreviewItems();
		const hasFullSyncPreview = latestPreview !== null && (latestPreviewMode === "full" || Boolean(latestPreview?.forceFull));
		const runningFullSync = getIsRunningFullSync();
		const resumableFullSync = getHasResumableFullSync();

		previewButton.disabled = busy || !hasSelection;
		runButton.disabled = busy || !hasSelection || !hasPreviewChanges || !hasSelectedPreviewItems || runningFullSync || resumableFullSync;
		fullSyncButton.disabled = (busy && !runningFullSync) || !hasSelection || hasFullSyncPreview || runningFullSync || resumableFullSync;
		pauseSyncButton.disabled = !runningFullSync;
		resumeSyncButton.disabled = runningFullSync || !resumableFullSync;
		runButton.textContent = busy ? (config.strings.syncingAction || "Syncing...") : runLabel;
		fullSyncButton.textContent = config.strings.fullSync || "Full Sync";
		pauseSyncButton.textContent = currentJob?.pauseRequested ? (config.strings.pausePending || "Pause requested") : (config.strings.pauseSync || "Pause Sync");
		resumeSyncButton.textContent = config.strings.resumeSync || "Resume Sync";

		if (manualBaselineButton) {
			manualBaselineButton.disabled = busy || !hasSelection;
		}
	};

	const setBusy = (isBusy) => {
		busy = isBusy;
		updateConnectionControls();
		updateRemoteUpdateControls();
		updateActionButtons();
	};

	const applyScopeStatus = (scopeStatus) => {
		if (!scopeStatus || !Array.isArray(scopeStatus.pendingBaselineScopeIds)) {
			return;
		}

		pendingBaselineScopeIds = new Set(scopeStatus.pendingBaselineScopeIds.map(String));
		updateScopeRows();
		updateActionButtons();
	};

	const renderConnectionResult = (payload, isError = false) => {
		if (!connectionPanel || !connectionBadge || !connectionMessage || !connectionMeta) {
			return;
		}

		connectionPanel.classList.remove("is-hidden");
		connectionBadge.textContent = isError ? (config.strings.connectionError || "Connection failed") : (config.strings.connectionReady || "Connection ready");
		connectionMessage.textContent = isError
			? payload.message || config.strings.unknownError || "Synchy hit an unexpected Sync error."
			: payload.message || "Destination site is ready for Sync.";

		if (isError) {
			renderMeta(connectionMeta, []);
			return;
		}

		renderMeta(connectionMeta, [
			{ label: config.strings.site || "Site", value: payload.name || "" },
			{ label: config.strings.destination || "Destination", value: payload.siteUrl || "" },
			{ label: config.strings.localPluginVersion || "Local plugin version", value: config.localPluginVersion || "" },
			{ label: config.strings.pluginVersion || "Plugin version", value: payload.pluginVersion || "" },
			{ label: config.strings.authenticatedAs || "Authenticated as", value: payload.authenticatedAs || "" },
		]);
	};

	const updateRemoteUpdateControls = () => {
		if (!updateRemoteButton || !updateRemoteNote) {
			return;
		}

		const remoteVersion = String(currentConnectionState?.remoteSite?.pluginVersion || "");
		const localVersion = String(config.localPluginVersion || "");
		const canCompare = remoteVersion !== "" && localVersion !== "";
		const remoteIsOlder = canCompare && compareVersions(remoteVersion, localVersion) < 0;

		updateRemoteButton.classList.toggle("is-hidden", !remoteIsOlder);
		updateRemoteButton.disabled = busy || !remoteIsOlder;
		updateRemoteNote.textContent = remoteIsOlder
			? `${config.strings.updateAvailable || "Destination update available"} ${remoteVersion} -> ${localVersion}`
			: (canCompare
				? (config.strings.destinationUpToDate || "Destination Synchy is up to date.")
				: (config.strings.updateCheckPending || "Run or wait for the connection check to compare Synchy versions."));
	};

	const performConnectionTest = async () => {
		try {
			const data = await sendAjax("synchy_test_sync_connection");
			currentConnectionState = {
				status: "connected",
				message: config.strings.connectionReady || "Connection ready",
				remoteSite: data.remoteSite || {},
			};
			connectionVerified = true;
			renderConnectionResult(data.remoteSite || {}, false);
			updateConnectionControls();
			updateRemoteUpdateControls();
			return { ok: true, remoteSite: data.remoteSite || {} };
		} catch (error) {
			currentConnectionState = {
				status: "error",
				message: error.message,
				remoteSite: {},
			};
			connectionVerified = false;
			renderConnectionResult({ message: error.message }, true);
			updateConnectionControls();
			updateRemoteUpdateControls();
			return { ok: false, message: error.message };
		}
	};

	const updateRemoteSynchy = async () => {
		if (!window.confirm(config.strings.confirmUpdateRemoteSynchy || "Update Synchy on the destination site from this local plugin copy now?")) {
			return;
		}

		setBusy(true);

		try {
			const data = await sendAjax("synchy_update_remote_synchy");

			if (data.remoteSite) {
				currentConnectionState = {
					status: "connected",
					message: data.message || config.strings.destinationUpdated || "Destination Synchy updated.",
					remoteSite: data.remoteSite,
				};
				connectionVerified = true;
				renderConnectionResult(data.remoteSite, false);
				updateConnectionControls();
				updateRemoteUpdateControls();
				refreshRemoteVersionUntilCurrent();
			}
		} catch (error) {
			renderConnectionResult({ message: error.message }, true);
			updateRemoteUpdateControls();
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const renderPreviewTree = (preview) => {
		if (!previewTreeContainer) {
			return;
		}

		const activeBatchSource = Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
			? currentJob.batches
			: Array.isArray(preview?.batches) ? preview.batches : [];

		if (activeBatchSource.length > 0) {
			changedScopeIds = new Set(activeBatchSource.map((batch) => String(batch.scopeId || "")).filter(Boolean));
			updateScopeRows();
			previewTreeContainer.innerHTML = `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.batches || "Batches")}</h4>
					${activeBatchSource.map((batch) => {
						const status = String(batch?.status || "pending");
						const marker = status === "complete" ? "[x]" : status === "running" ? "[>]" : status === "failed" ? "[!]" : status === "paused" ? "[|]" : "[ ]";
						const detail = Number(batch?.fileCount || 0) > 0
							? `${Number(batch.fileCount || 0).toLocaleString()} files • ${formatBytes(batch.workUnits || 0)}`
							: `${Number(batch?.dbRows || 0).toLocaleString()} rows`;

						return `
							<div class="synchy-sync-tree__node">
								<div class="synchy-sync-tree__toggle">
									<span>
										<strong>${escapeHtml(`${marker} ${batch?.label || ""}`)}</strong>
										<small>${escapeHtml(detail)}</small>
									</span>
								</div>
								${batch?.error ? `<p class="synchy-sync-tree__sample">${escapeHtml(batch.error)}</p>` : ""}
							</div>
						`;
					}).join("")}
				</div>
			`;
			previewTreeContainer.classList.remove("is-hidden");
			renderPreviewBatchCounter(preview);
			updateActionButtons();
			return;
		}

		const tree = preview?.previewTree || null;
		const fileGroups = Array.isArray(tree?.fileGroups) ? tree.fileGroups : [];
		const databaseTables = Array.isArray(tree?.databaseTables) ? tree.databaseTables : [];
		const nextChangedScopeIds = new Set();

		fileGroups.forEach((group) => {
			if (group?.id) {
				nextChangedScopeIds.add(String(group.id));
			}
		});

		databaseTables.forEach((table) => {
			if (table?.scopeId) {
				nextChangedScopeIds.add(String(table.scopeId));
			}
		});

		changedScopeIds = nextChangedScopeIds;
		updateScopeRows();

		if (fileGroups.length === 0 && databaseTables.length === 0) {
			previewTreeContainer.innerHTML = "";
			previewTreeContainer.classList.add("is-hidden");
			renderPreviewBatchCounter(preview);
			updateActionButtons();
			return;
		}

		const existingFileSelection = new Set(
			Array.from(form.querySelectorAll('input[name="synchy_sync_selected_file_scopes[]"]:checked')).map((input) => String(input.value || ""))
		);
		const existingTableSelection = new Set(
			Array.from(form.querySelectorAll('input[name="synchy_sync_selected_db_tables[]"]:checked')).map((input) => String(input.value || ""))
		);
		const hasExistingSelection = existingFileSelection.size > 0 || existingTableSelection.size > 0;
		const isChecked = (value, set) => (!hasExistingSelection ? true : set.has(String(value)));
		const selectedScopeIds = getSelectedScopeIdSet();

		const fileGroupHtml = fileGroups
			.map((group) => {
				const files = Array.isArray(group.files) ? group.files : [];
				const buckets = buildFileBuckets(String(group.id || ""), files);

				return `
					<div class="synchy-sync-tree__node">
						<label class="synchy-sync-tree__toggle">
							<input
								type="checkbox"
								name="synchy_sync_selected_file_scopes[]"
								value="${escapeHtml(group.id || "")}"
								data-synchy-preview-selection
								data-scope-id="${escapeHtml(group.id || "")}"
								${isChecked(group.id || "", existingFileSelection) ? "checked" : ""}
								${selectedScopeIds.has(String(group.id || "")) ? "" : "disabled"}
							/>
							<span>
								<strong>${escapeHtml(group.label || "")}</strong>
								<small>${escapeHtml(String(group.count || 0))} files • ${escapeHtml(formatBytes(group.bytes || 0))}</small>
							</span>
						</label>
						<div class="synchy-sync-tree__groups">
							${buckets.map((bucket) => {
								const visibleFiles = bucket.files.slice(0, 100);
								return `
									<details class="synchy-sync-tree__details">
										<summary>${escapeHtml(bucket.label)} <span>${escapeHtml(String(bucket.count))} files • ${escapeHtml(formatBytes(bucket.bytes))}</span></summary>
										<ul class="synchy-sync-tree__list">
											${visibleFiles.map((file) => `<li><span>${escapeHtml(file.path)}</span><small>${escapeHtml(formatBytes(file.size))}</small></li>`).join("")}
											${bucket.files.length > visibleFiles.length ? `<li><span>${escapeHtml(`... and ${bucket.files.length - visibleFiles.length} more files`)}</span></li>` : ""}
										</ul>
									</details>
								`;
							}).join("")}
						</div>
					</div>
				`;
			})
			.join("");

		const dbTableHtml = databaseTables
			.map((table) => {
				const rowIds = Array.isArray(table.rowIds) ? table.rowIds : [];

				return `
					<div class="synchy-sync-tree__node">
						<label class="synchy-sync-tree__toggle">
							<input
								type="checkbox"
								name="synchy_sync_selected_db_tables[]"
								value="${escapeHtml(table.table || "")}"
								data-synchy-preview-selection
								data-scope-id="${escapeHtml(table.scopeId || "")}"
								${isChecked(table.table || "", existingTableSelection) ? "checked" : ""}
								${selectedScopeIds.has(String(table.scopeId || "")) ? "" : "disabled"}
							/>
							<span>
								<strong>${escapeHtml(table.label || "")}</strong>
								<small>${escapeHtml(String(table.rowCount || 0))} rows${table.scopeLabel ? ` • ${escapeHtml(table.scopeLabel)}` : ""}</small>
							</span>
						</label>
						${rowIds.length > 0 ? `<p class="synchy-sync-tree__sample">${escapeHtml(config.strings.sampleRowIds || "Sample row IDs")}: ${escapeHtml(rowIds.join(", "))}</p>` : ""}
					</div>
				`;
			})
			.join("");

		previewTreeContainer.innerHTML = `
			<input type="hidden" name="synchy_sync_preview_selection_present" value="1" data-synchy-preview-selection-marker />
			${fileGroups.length > 0 ? `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.files || "Files")}</h4>
					${fileGroupHtml}
				</div>
			` : ""}
			${databaseTables.length > 0 ? `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.dbTables || "Database tables")}</h4>
					${dbTableHtml}
				</div>
			` : ""}
		`;
		previewTreeContainer.classList.remove("is-hidden");
		renderPreviewBatchCounter(preview);
		updateActionButtons();
	};

	const renderPreview = (preview) => {
		if (!preview) {
			if (getIsRunningFullSync() || getHasResumableFullSync()) {
				previewBadge.textContent = config.strings.fullSync || "Full Sync";
				previewMessage.textContent = currentJob?.message || (config.strings.previewDefault || "Run Preview Changes to load the pending file sections and database tables.");
			} else {
				previewBadge.textContent = "";
				previewMessage.textContent = config.strings.previewDefault || "Run Preview Changes to load the pending file sections and database tables.";
			}
			renderPreviewBatchCounter(null);
			renderPreviewTree(null);
			return;
		}

		const mode = String(preview.mode || "delta").toLowerCase() === "baseline"
			? (config.strings.baseline || "Baseline")
			: (config.strings.delta || "Delta");
		const filesCount = Number(preview.filesCount || 0);
		const dbRows = Number(preview.dbRows || 0);
		previewBadge.textContent = mode;

		if (filesCount === 0 && dbRows === 0) {
			previewMessage.textContent = "No pending changes detected since the last successful Sync.";
		} else if (Array.isArray(preview?.batches) && preview.batches.length > 0) {
			previewMessage.textContent = `Full Sync will run ${Number(preview.totalBatches || 0).toLocaleString()} logical batches for the selected scopes.`;
		} else {
			previewMessage.textContent = config.strings.previewSelectionHelp || "Review the pending file sections and database tables, then uncheck anything you do not want to send.";
		}

		renderPreviewTree(preview);
	};

	const getStatusBadge = (status) => {
		switch (String(status?.status || "")) {
			case "success":
				return config.strings.success || "Success";
			case "paused":
				return config.strings.paused || "Paused";
			case "error":
				return config.strings.error || "Error";
			case "idle":
				return config.strings.noChanges || "No changes";
			default:
				return config.strings.awaitingBaseline || "Awaiting baseline";
		}
	};

	const getStatusMessage = (status) => {
		if (status && status.message) {
			return status.message;
		}

		return "No Sync has completed yet.";
	};

	const buildStatusSummary = (status) => {
		if (["error", "paused"].includes(String(status?.status || ""))) {
			return getStatusMessage(status);
		}

		const lastSync = formatDateTime(status?.lastSyncTime || "");
		const destination = status?.destinationUrl || "";
		const files = Number(status?.filesSynced || 0).toLocaleString();
		const dbRows = Number(status?.dbRowsSynced || 0).toLocaleString();
		const mode = String(status?.mode || "").toLowerCase() === "baseline"
			? (config.strings.baseline || "Baseline")
			: String(status?.mode || "") === ""
				? (config.strings.delta || "Delta")
				: (config.strings.delta || "Delta");
		const duration = formatDuration(status?.durationSeconds || 0);

		return `Last Sync: ${lastSync} | ${destination || "Not set"} | ${files} files | ${dbRows} DB rows | ${mode} | ${duration}`;
	};

	const renderStatus = (status) => {
		statusBadge.textContent = getStatusBadge(status);
		statusSummary.textContent = buildStatusSummary(status);
	};

	const clearPreview = () => {
		latestPreview = null;
		latestPreviewMode = "delta";
		changedScopeIds = new Set();
		renderPreview(null);
		updateScopeRows();
		updateActionButtons();
	};

	const collectFormData = (action, extraFields = {}) => {
		const formData = new FormData(form);
		formData.append("action", action);
		formData.append("nonce", config.nonce);

		Object.entries(extraFields).forEach(([key, value]) => {
			formData.append(key, value);
		});

		return formData;
	};

	const sendAjax = async (action, extraFields = {}) => {
		const response = await fetch(config.ajaxUrl, {
			method: "POST",
			body: collectFormData(action, extraFields),
			credentials: "same-origin",
		});

		const raw = await response.text();
		let payload = null;

		try {
			payload = raw ? JSON.parse(raw) : null;
		} catch (error) {
			payload = null;
		}

		if (!response.ok || !payload || payload.success !== true) {
			const message = payload?.data?.message || payload?.message || config.strings.unknownError || "Synchy hit an unexpected Sync error.";
			throw new Error(message);
		}

		return payload.data || {};
	};

	const pollSyncJob = async () => {
		if (!busy) {
			return;
		}

		try {
			const data = await sendAjax("synchy_get_sync_job_status");
			currentJob = data.job || null;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview);

			if (currentJob && currentJob.status === "running") {
				window.setTimeout(pollSyncJob, 250);
				return;
			}
		} catch (error) {
			if (busy) {
				window.setTimeout(pollSyncJob, 500);
			}
		}
	};

	const requireSelection = () => {
		if (getHasSelection()) {
			return true;
		}

		previewBadge.textContent = config.strings.previewError || "Preview failed";
		previewMessage.textContent = config.strings.selectAtLeastOneScope || "Select at least one file or database scope first.";
		return false;
	};

	const runTestConnection = async () => {
		setBusy(true);

		try {
			await performConnectionTest();
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const runPreview = async (mode = "delta") => {
		if (!requireSelection()) {
			updateActionButtons();
			return;
		}

		setBusy(true);

		try {
			if (!hasConfirmedConnection()) {
				const connectionCheck = await performConnectionTest();

				if (!connectionCheck.ok) {
					previewBadge.textContent = config.strings.previewError || "Preview failed";
					previewMessage.textContent = connectionCheck.message || config.strings.connectionError || "Connection failed";
					clearPreview();
					return;
				}
			}

			const data = await sendAjax("synchy_preview_sync_changes", {
				synchy_sync_run_mode: mode === "full" ? "full" : "delta",
			});
			latestPreview = data.preview || null;
			latestPreviewMode = mode === "full" ? "full" : "delta";
			applyScopeStatus(data.scopeStatus || null);
			if (data.remoteSite) {
				currentConnectionState = {
					status: "connected",
					message: config.strings.connectionReady || "Connection ready",
					remoteSite: data.remoteSite,
				};
				connectionVerified = true;
				renderConnectionResult(data.remoteSite || {}, false);
			}
			renderPreview(latestPreview);
		} catch (error) {
			clearPreview();
			previewBadge.textContent = config.strings.previewError || "Preview failed";
			previewMessage.textContent = error.message;
		} finally {
			setBusy(false);
		}
	};

	const runManualBaseline = async () => {
		if (!requireSelection()) {
			updateActionButtons();
			return;
		}

		const destinationUrl = destinationUrlInput?.value?.trim() || "";
		const scopeLabels = getSelectedScopeLabels();
		const confirmMessage = [
			config.strings.confirmBaseline || "Mark the selected scopes as already baselined after a successful manual full restore to the destination site?",
			"",
			`Destination: ${destinationUrl || "Not set"}`,
			`Scopes: ${scopeLabels.join(", ") || "None"}`,
		].join("\n");

		if (!window.confirm(confirmMessage)) {
			return;
		}

		setBusy(true);
		statusBadge.textContent = config.strings.syncingAction || "Syncing...";
		statusSummary.textContent = "Saving the selected manual baseline state.";

		try {
			const data = await sendAjax("synchy_mark_sync_baseline_complete");
			renderStatus(data.status || {});
			applyScopeStatus(data.scopeStatus || null);
			clearPreview();
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
				lastSyncTime: "",
				filesSynced: 0,
				dbRowsSynced: 0,
				durationSeconds: 0,
				destinationUrl: destinationUrl || "",
				mode: "",
			});
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const runSync = async () => {
		if (latestPreview === null) {
			return;
		}

		const destinationUrl = destinationUrlInput?.value?.trim() || "";
		const scopeLabels = getSelectedScopeLabels();
		const selectedFileSections = form.querySelectorAll('input[name="synchy_sync_selected_file_scopes[]"]:checked').length;
		const selectedDbTables = form.querySelectorAll('input[name="synchy_sync_selected_db_tables[]"]:checked').length;
		const isFullSync = latestPreviewMode === "full" || Boolean(latestPreview?.forceFull);
		const confirmMessage = [
			isFullSync
				? (config.strings.confirmFullSync || "Run a full Sync for the selected scopes and send all tracked files and rows to the destination site now?")
				: (config.strings.confirmSync || "Sync the previewed changes to the destination site now?"),
			"",
			`Destination: ${destinationUrl || "Not set"}`,
			`Scopes: ${scopeLabels.join(", ") || "None"}`,
			isFullSync
				? `Planned batches: ${Number(latestPreview?.totalBatches || 0).toLocaleString()}`
				: `Selected preview items: ${selectedFileSections} file sections, ${selectedDbTables} DB tables`,
		].join("\n");

		if (!window.confirm(confirmMessage)) {
			return;
		}

		setBusy(true);
		currentJob = {
			status: "running",
			runMode: isFullSync ? "full" : "delta",
			phase: "building_package",
			phaseLabel: config.strings.syncRunning || "Sync running",
			progress: 5,
			message: "Starting Sync...",
			filesCount: Number(latestPreview?.filesCount || 0),
			dbRows: Number(latestPreview?.dbRows || 0),
			totalBatches: Number(latestPreview?.totalBatches || 0),
			completedBatches: 0,
			currentBatchLabel: "",
			batches: Array.isArray(latestPreview?.batches) ? latestPreview.batches : [],
			stages: Array.isArray(config.defaultStages) ? config.defaultStages : [],
		};
		renderProgress(currentJob);
		renderPreviewTree(latestPreview);
		window.setTimeout(pollSyncJob, 100);
		statusBadge.textContent = config.strings.syncingAction || "Syncing...";
		statusSummary.textContent = "Sync is running. Keep this tab open until it finishes.";

		try {
			const data = await sendAjax("synchy_run_sync_changes", {
				synchy_sync_run_mode: isFullSync ? "full" : "delta",
			});
			currentJob = data.job || null;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview);
			renderStatus(data.status || {});
			applyScopeStatus(data.scopeStatus || null);
			if (!getHasResumableFullSync()) {
				clearPreview();
			}
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
				lastSyncTime: "",
				filesSynced: 0,
				dbRowsSynced: 0,
				durationSeconds: 0,
				destinationUrl: destinationUrl || "",
				mode: "",
			});
		} finally {
			setBusy(false);
		}
	};

	const pauseFullSync = async () => {
		try {
			const data = await sendAjax("synchy_pause_full_sync");
			currentJob = data.job || null;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview);
			updateActionButtons();
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
			});
		}
	};

	const resumeFullSync = async () => {
		if (!window.confirm(config.strings.confirmResumeSync || "Resume the remaining full Sync batches now?")) {
			return;
		}

		setBusy(true);
		currentJob = {
			...(currentJob || {}),
			status: "running",
			runMode: "full",
			pauseRequested: false,
			phase: "sending_package",
			phaseLabel: config.strings.syncRunning || "Sync running",
			message: "Resuming Sync...",
		};
		renderProgress(currentJob);
		renderPreviewTree(latestPreview);
		window.setTimeout(pollSyncJob, 100);

		try {
			const data = await sendAjax("synchy_resume_full_sync");
			currentJob = data.job || null;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview);
			renderStatus(data.status || {});
			applyScopeStatus(data.scopeStatus || null);
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
			});
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	form.addEventListener("input", (event) => {
		if (event.target?.matches("[data-synchy-preview-selection]")) {
			updateActionButtons();
			return;
		}

		if (
			event.target === destinationUrlInput
			|| event.target === usernameInput
			|| event.target === passwordInput
		) {
			connectionVerified = false;
		}

		updateTargetNote();
		updateConnectionControls();
		updateActionButtons();
	});
	form.addEventListener("change", (event) => {
		if (event.target?.matches("[data-synchy-preview-selection]")) {
			updateActionButtons();
			return;
		}

		if (
			event.target === destinationUrlInput
			|| event.target === usernameInput
			|| event.target === passwordInput
			|| event.target === verifySslInput
		) {
			connectionVerified = false;
		}

		updateTargetNote();
		updateConnectionControls();
		updateActionButtons();
	});
	testButton.addEventListener("click", runTestConnection);
	if (updateRemoteButton) {
		updateRemoteButton.addEventListener("click", updateRemoteSynchy);
	}
	previewButton.addEventListener("click", () => runPreview("delta"));
	fullSyncButton.addEventListener("click", () => runPreview("full"));
	runButton.addEventListener("click", runSync);
	pauseSyncButton.addEventListener("click", pauseFullSync);
	resumeSyncButton.addEventListener("click", resumeFullSync);
	manualBaselineButton.addEventListener("click", runManualBaseline);

	updateTargetNote();
	updateScopeRows();
	renderProgress(currentJob);
	renderPreviewTree(latestPreview);
	updateRemoteUpdateControls();
	if (currentConnectionState?.status === "connected") {
		renderConnectionResult(currentConnectionState.remoteSite || {}, false);
	} else if (currentConnectionState?.status === "error") {
		renderConnectionResult({ message: currentConnectionState.message || (config.strings.connectionError || "Connection failed") }, true);
	}

	if (
		!autoConnectionCheckStarted
		&& destinationUrlInput.value.trim() !== ""
		&& usernameInput.value.trim() !== ""
		&& passwordInput.dataset.hasSavedPassword === "1"
	) {
		autoConnectionCheckStarted = true;
		window.setTimeout(runTestConnection, 50);
	}

	if (currentJob && currentJob.status === "running") {
		setBusy(true);
		window.setTimeout(pollSyncJob, 100);
		return;
	}

	updateConnectionControls();
	updateActionButtons();
})();
