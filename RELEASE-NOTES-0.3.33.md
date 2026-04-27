freeSIEM Sentinel 0.3.33

- Repairs synced WordPress navigation menus through WordPress menu APIs after the database package is applied, preserving live theme menu locations even when destination taxonomy rows differ.
- Replaces incoming menu and SureForms post meta before SQL apply so stale destination rows do not hide synced menu item settings or form button settings.
