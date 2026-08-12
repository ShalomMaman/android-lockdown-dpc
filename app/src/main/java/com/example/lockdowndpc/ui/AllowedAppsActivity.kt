package com.example.lockdowndpc.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.LockdownPackages
import com.example.lockdowndpc.policy.LockdownPolicyController
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.security.AppLabelSanitizer
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

private const val ICON_SIZE_DP = 40

/**
 * Selection of the managed applications. The inventory rules, the default
 * selection and what gets persisted are unchanged; the list is now searchable and
 * the save action is pinned to the bottom of the screen.
 *
 * `AppCompatActivity` is the base class for the same localization reason as
 * [MainActivity]: below API 33 it is what applies the persisted display language.
 */
class AllowedAppsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )

        val allowSelected = AllowedAppsStore.getProtectionMode(this) ==
            AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
        setTitle(if (allowSelected) R.string.apps_title_allow else R.string.apps_title_block)

        setContent {
            LockdownTheme {
                AllowedAppsScreen(
                    allowSelected = allowSelected,
                    onBack = { finish() },
                    onSave = ::saveAndClose,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!AdminSession.isUnlocked()) {
            finish()
        }
    }

    private fun saveAndClose(selected: Set<String>, managed: Set<String>) {
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        AllowedAppsStore.setAllowedPackages(this, selected, managed)
        AuditLog.append(this, getString(R.string.audit_apps_saved))
        if (AllowedAppsStore.isProtectionEnabled(this)) {
            LockdownPolicyController.apply(this)
        }
        AdminSession.extend()
        setResult(RESULT_OK)
        finish()
    }
}

private data class AppEntry(
    val packageName: String,
    val label: String,
    val icon: ImageBitmap?,
)

private data class LoadedApps(
    val entries: List<AppEntry>,
    val selection: Set<String>,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AllowedAppsScreen(
    allowSelected: Boolean,
    onBack: () -> Unit,
    onSave: (Set<String>, Set<String>) -> Unit,
) {
    val context = LocalContext.current
    val iconSizePx = with(context.resources.displayMetrics) { (ICON_SIZE_DP * density).toInt() }

    var loading by remember { mutableStateOf(true) }
    var entries by remember { mutableStateOf(emptyList<AppEntry>()) }
    var selected by remember { mutableStateOf(emptySet<String>()) }
    var query by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) {
            loadManagedApps(context, allowSelected, iconSizePx)
        }
        entries = loaded.entries
        selected = loaded.selection
        loading = false
    }

    val filtered = remember(entries, query) {
        entries.filter { matchesAppQuery(it.label, it.packageName, query) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(
                            if (allowSelected) R.string.apps_title_allow else R.string.apps_title_block
                        ),
                        style = MaterialTheme.typography.titleLarge,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.primary,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
        },
        bottomBar = {
            SaveBar(
                selectedCount = selected.size,
                totalCount = entries.size,
                enabled = !loading,
                onSave = {
                    onSave(selected, entries.mapTo(HashSet<String>()) { it.packageName })
                },
            )
        },
    ) { insets ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(insets),
        ) {
            Text(
                text = stringResource(
                    if (allowSelected) R.string.apps_note_allow else R.string.apps_note_block
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.apps_search)) },
                singleLine = true,
                shape = MaterialTheme.shapes.small,
                leadingIcon = {
                    Icon(imageVector = Icons.Rounded.Search, contentDescription = null)
                },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(
                                imageVector = Icons.Rounded.Close,
                                contentDescription = stringResource(R.string.apps_search_clear),
                            )
                        }
                    }
                },
                // A query is as likely to be a package-name fragment as a Hebrew
                // label, so the field resolves its own direction from what was
                // typed instead of inheriting the page's — the platform
                // equivalent of `dir="auto"` on an input.
                textStyle = LocalTextStyle.current.copy(textDirection = TextDirection.Content),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
            )
            Spacer(Modifier.height(12.dp))

            when {
                loading -> CenteredState(Modifier.weight(1f)) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(20.dp))
                    Text(
                        text = stringResource(R.string.apps_loading),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                entries.isEmpty() -> CenteredState(Modifier.weight(1f)) {
                    EmptyState(
                        title = stringResource(R.string.apps_empty_title),
                        body = stringResource(R.string.apps_empty_body),
                    )
                }

                filtered.isEmpty() -> CenteredState(Modifier.weight(1f)) {
                    EmptyState(
                        title = stringResource(R.string.apps_no_results_title),
                        body = stringResource(R.string.apps_no_results_body),
                    )
                }

                else -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(bottom = 16.dp),
                ) {
                    items(filtered, key = { it.packageName }) { entry ->
                        AppRow(
                            entry = entry,
                            checked = entry.packageName in selected,
                            onCheckedChange = { checked ->
                                selected = if (checked) {
                                    selected + entry.packageName
                                } else {
                                    selected - entry.packageName
                                }
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SaveBar(
    selectedCount: Int,
    totalCount: Int,
    enabled: Boolean,
    onSave: () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.surface, tonalElevation = 3.dp) {
        Column(modifier = Modifier.fillMaxWidth()) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp, vertical = 14.dp),
            ) {
                Text(
                    // Hebrew inflects the verb for one, two and many selections,
                    // so the counter is a plural rather than one format string.
                    text = pluralStringResource(
                        R.plurals.apps_selected_count,
                        selectedCount,
                        selectedCount,
                        totalCount,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                PrimaryAction(
                    text = stringResource(R.string.apps_save),
                    icon = Icons.Rounded.Check,
                    enabled = enabled,
                    onClick = onSave,
                )
            }
        }
    }
}

@Composable
private fun CenteredState(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(32.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) { content() }
    }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Icon(
        imageVector = Icons.Rounded.Apps,
        contentDescription = null,
        tint = MaterialTheme.colorScheme.outline,
        modifier = Modifier.size(48.dp),
    )
    Spacer(Modifier.height(16.dp))
    Text(text = title, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    Text(
        text = body,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun AppRow(
    entry: AppEntry,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    val description = stringResource(
        R.string.apps_row_description,
        entry.label,
        entry.packageName,
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .toggleable(
                value = checked,
                role = Role.Checkbox,
                onValueChange = onCheckedChange,
            )
            .semantics(mergeDescendants = true) { contentDescription = description }
            .padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Start,
    ) {
        AppIcon(entry.icon)
        Spacer(Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                // A third-party label can be in any language, so it is isolated
                // without forcing a direction and is allowed a second line at
                // large font scales.
                text = entry.label.bidiIsolated(),
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                // Package names are Latin identifiers that may sit inside a
                // right-to-left paragraph, so they are isolated left-to-right to
                // keep the dot-separated segments in order.
                text = entry.packageName.ltrIsolated(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.size(12.dp))
        Checkbox(checked = checked, onCheckedChange = null)
    }
}

@Composable
private fun AppIcon(icon: ImageBitmap?) {
    if (icon != null) {
        Image(
            bitmap = icon,
            contentDescription = null,
            modifier = Modifier.size(ICON_SIZE_DP.dp),
        )
        return
    }
    Box(
        modifier = Modifier
            .size(ICON_SIZE_DP.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.Rounded.Apps,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
    }
}

/**
 * Mirrors the inventory rules of the previous implementation: every package that
 * is installed for this user or that we have managed before, minus system
 * packages, this DPC, the management transport and the packages that are always
 * blocked.
 *
 * The management transport is read from [LockdownPackages.managementPackageNames]
 * rather than from a package-name literal, so this list, the policy engine and
 * the kiosk target rules all exclude exactly the same set.
 */
private fun loadManagedApps(
    context: Context,
    allowSelected: Boolean,
    iconSizePx: Int,
): LoadedApps {
    val pm = context.packageManager
    val managementPackages = LockdownPackages.managementPackageNames()
    val allowed = AllowedAppsStore.getAllowedPackages(context)
    val configured = AllowedAppsStore.isAllowlistConfigured(context)
    val managed = AllowedAppsStore.getManagedPackages(context)

    val inventoryFlags = (
        PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS
        ).toLong()
    val installed: List<ApplicationInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(inventoryFlags))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(inventoryFlags.toInt())
        }

    // MATCH_UNINSTALLED_PACKAGES can also return packages whose APK was removed
    // but whose data was retained. Keep only applications installed for this
    // user; DPC-hidden applications retain FLAG_INSTALLED.
    val installedByPackage = LinkedHashMap<String, ApplicationInfo>()
    for (info in installed) {
        if (info.flags and ApplicationInfo.FLAG_INSTALLED != 0) {
            installedByPackage[info.packageName] = info
        }
    }

    val candidates = LinkedHashSet(installedByPackage.keys)
    candidates.addAll(managed)

    val entries = ArrayList<AppEntry>()
    for (packageName in candidates) {
        val info = installedByPackage[packageName] ?: loadApplicationInfo(pm, packageName)
        val system = info != null &&
            info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        if (system || packageName == context.packageName || packageName in managementPackages) {
            continue
        }
        if (packageName in LockdownPackages.ALWAYS_BLOCKED ||
            packageName in LockdownPackages.KNOWN_BROWSER_AND_SOCIAL
        ) {
            continue
        }

        val label = AppLabelSanitizer.sanitize(info?.loadLabel(pm)?.toString())
            ?: AllowedAppsStore.getRememberedLabel(context, packageName)
        AllowedAppsStore.rememberManagedPackage(context, packageName, label)
        entries.add(AppEntry(packageName, label, loadIcon(pm, packageName, iconSizePx)))
    }
    entries.sortBy { it.label.lowercase(Locale.getDefault()) }

    val selection = entries
        .filter { if (configured) it.packageName in allowed else allowSelected }
        .mapTo(HashSet<String>()) { it.packageName }
    return LoadedApps(entries, selection)
}

private fun loadApplicationInfo(pm: PackageManager, packageName: String): ApplicationInfo? = try {
    val flags = (
        PackageManager.MATCH_DISABLED_COMPONENTS or PackageManager.MATCH_UNINSTALLED_PACKAGES
        ).toLong()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags))
    } else {
        @Suppress("DEPRECATION")
        pm.getApplicationInfo(packageName, flags.toInt())
    }
} catch (ignored: PackageManager.NameNotFoundException) {
    null
}

/** Best-effort launcher icon; hidden or broken packages simply fall back to a glyph. */
private fun loadIcon(pm: PackageManager, packageName: String, sizePx: Int): ImageBitmap? = try {
    pm.getApplicationIcon(packageName)
        .toBitmap(width = sizePx, height = sizePx, config = Bitmap.Config.ARGB_8888)
        .asImageBitmap()
} catch (ignored: PackageManager.NameNotFoundException) {
    null
} catch (ignored: RuntimeException) {
    null
}
