# Package-install reconciliation

On Android 8.0 and newer, most implicit package broadcasts are not delivered to a receiver declared only in the manifest. `PACKAGE_ADDED` is therefore handled by a dynamic receiver inside `LockdownDeviceAdminService` rather than by the static receiver.

Android keeps a Device Owner's `DeviceAdminService` bound while the user is active. If memory pressure kills the process, the system rebinds it after backoff. The service also performs a full reconciliation in `onCreate()`, so a restarted process repairs package changes that occurred while it was unavailable.

Behavior depends on the selected policy mode:

- In allowlist mode (`ALLOW_SELECTED`), every newly installed third-party app enters the managed inventory and is blocked until explicitly approved.
- In blocklist mode (`BLOCK_SELECTED`), known blocked packages are blocked again, while an arbitrary new app remains allowed by definition.
- If protection was not requested, the service does not apply blocking. A later activation performs a full scan rather than relying only on broadcast history.

Operations run through one executor, and `apply()`/`pause()` are synchronized to avoid concurrent reconciliation from installation, boot, and the administration UI.

## Remaining limitation

`PACKAGE_ADDED` arrives after installation completes, so a short interval can exist between installation and package hiding. Fully atomic enforcement requires control over the installation path itself, such as managed app distribution, with ADB and external installers unavailable while protection is active. Existing restrictions on stores, unknown sources, and app control reduce this interval on the normal user path.

Official references: [`DeviceAdminService`](https://developer.android.com/reference/android/app/admin/DeviceAdminService), [implicit broadcast exceptions](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions), and [`ACTION_PACKAGE_ADDED`](https://developer.android.com/reference/android/content/Intent#ACTION_PACKAGE_ADDED).
