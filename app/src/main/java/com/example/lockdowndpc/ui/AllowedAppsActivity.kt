package com.example.lockdowndpc.ui

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
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
import com.example.lockdowndpc.policy.LockdownPolicyController
import com.example.lockdowndpc.policy.SystemAppClassifier.Category
import com.example.lockdowndpc.policy.SystemAppClassifier.Origin
import com.example.lockdowndpc.policy.SystemAppClassifier.ProtectedContext
import com.example.lockdowndpc.policy.SystemAppClassifier.ReasonKey
import com.example.lockdowndpc.policy.SystemAppClassifier.RiskAcceptanceStatus
import com.example.lockdowndpc.policy.SystemAppClassifier.RowState
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val ICON_SIZE_DP = 40

/**
 * The searchable application inventory (Issue #18).
 *
 * It lists every application on the device — user, system and updated-system —
 * plus the packages Device Guard has hidden, which `PackageManager` omits from
 * bulk queries and which would otherwise disappear from the very screen that
 * blocked them.
 *
 * What an administrator may change is deliberately narrower than what they can
 * see. `SystemAppClassifier` decides that, and it is at least as conservative as
 * the policy engine: a protected package and a package a built-in catalogue
 * already rules on are shown with their reason and no checkbox, so the screen
 * never offers a choice the next reconciliation pass would overrule.
 *
 * Applying the result stays entirely with `LockdownPolicyController`, which owns
 * the requested → applied/failed contract. This screen never reports protection
 * as active on its own.
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
        setTitle(R.string.sysinv_title)

        setContent {
            LockdownTheme {
                InventoryScreen(
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

    /**
     * Persists both halves of the decision and hands application to the policy
     * engine.
     *
     * The guarded system-package store is written first and separately: it is the
     * only gate that puts a system package under allow/block control, and it
     * strips the protected catalogues again on write, so a defect in this screen
     * still cannot make an essential package blockable.
     */
    private fun saveAndClose(
        adminSelectedSystem: Set<String>,
        selection: Set<String>,
        managed: Set<String>,
    ) {
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        val hadSystemSelection = AllowedAppsStore
            .getAdminSelectedSystemPackages(this).isNotEmpty() || adminSelectedSystem.isNotEmpty()

        AllowedAppsStore.setAdminSelectedSystemPackages(this, adminSelectedSystem)
        AllowedAppsStore.setAllowedPackages(this, selection, managed)
        AuditLog.append(this, getString(R.string.audit_apps_saved))
        if (hadSystemSelection) {
            AuditLog.append(this, getString(R.string.sysinv_audit_system_saved))
        }
        // The controller owns the requested → applied/failed contract and marks
        // the policy state itself. Nothing here may pre-announce success.
        if (AllowedAppsStore.isProtectionEnabled(this)) {
            LockdownPolicyController.apply(this)
        }
        AdminSession.extend()
        setResult(RESULT_OK)
        finish()
    }
}

private data class InventoryUiState(
    val rows: List<InventoryRow> = emptyList(),
    val protectedContext: ProtectedContext = ProtectedContext("", emptySet(), emptySet(), "", ""),
    val ticked: Set<String> = emptySet(),
    val optedInSystem: Set<String> = emptySet(),
    val firmwareBuild: String = "",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InventoryScreen(
    allowSelected: Boolean,
    onBack: () -> Unit,
    onSave: (Set<String>, Set<String>, Set<String>) -> Unit,
) {
    val context = LocalContext.current

    var loading by remember { mutableStateOf(true) }
    var state by remember { mutableStateOf(InventoryUiState()) }
    var query by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(Category.ALL) }
    var riskRow by remember { mutableStateOf<InventoryRow?>(null) }
    var confirmingSave by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) { loadInventory(context, allowSelected) }
        state = InventoryUiState(
            rows = loaded.rows,
            protectedContext = loaded.protectedContext,
            ticked = loaded.ticked,
            optedInSystem = loaded.optedInSystem,
            firmwareBuild = loaded.firmwareBuild,
        )
        loading = false
    }

    val visible = remember(state.rows, category, query) {
        filterInventory(state.rows, state.protectedContext, category, query)
    }
    val adminSelectedSystem = remember(state.rows, state.optedInSystem) {
        adminSelectedSystemPackages(state.rows, state.optedInSystem)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.sysinv_title),
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
                systemCount = adminSelectedSystem.size,
                enabled = !loading,
                onSave = { confirmingSave = true },
            )
        },
    ) { insets ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(insets),
        ) {
            Text(
                text = stringResource(R.string.sysinv_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                // What a tick means depends on the protection method in force, so
                // the screen restates it rather than assuming the operator
                // remembers which radio button they left selected.
                text = stringResource(
                    if (allowSelected) R.string.apps_note_allow else R.string.apps_note_block,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.sysinv_search)) },
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
                                contentDescription = stringResource(R.string.sysinv_search_clear),
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
            CategoryFilters(selected = category, onSelect = { category = it })
            Spacer(Modifier.height(8.dp))

            when {
                loading -> CenteredState(Modifier.weight(1f)) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(20.dp))
                    Text(
                        text = stringResource(R.string.sysinv_loading),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                visible.isEmpty() -> CenteredState(Modifier.weight(1f)) {
                    EmptyState(
                        title = stringResource(R.string.sysinv_no_results_title),
                        body = stringResource(R.string.sysinv_no_results_body),
                    )
                }

                else -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(bottom = 16.dp),
                ) {
                    items(visible, key = { it.packageName }) { row ->
                        val ticked = row.packageName in state.ticked
                        InventoryRowItem(
                            row = row,
                            ticked = ticked,
                            rowState = pendingRowState(row, ticked, allowSelected),
                            onTickedChange = { checked ->
                                state = state.copy(
                                    ticked = if (checked) {
                                        state.ticked + row.packageName
                                    } else {
                                        state.ticked - row.packageName
                                    },
                                    // Touching a manageable system row is what opts
                                    // it into management, in either direction: in
                                    // "allow only what I select", clearing the box
                                    // is how a system package gets blocked, so an
                                    // untick has to opt it in too. A row nobody
                                    // touched stays outside the policy entirely.
                                    optedInSystem = if (row.isAdminSelectableSystem) {
                                        state.optedInSystem + row.packageName
                                    } else {
                                        state.optedInSystem
                                    },
                                )
                            },
                            onReview = { riskRow = row },
                        )
                    }
                }
            }
        }
    }

    riskRow?.let { row ->
        RiskAcceptanceDialog(
            row = row,
            firmwareBuild = state.firmwareBuild,
            onDismiss = { riskRow = null },
            onAccept = {
                AllowedAppsStore.recordSystemRiskAcceptance(
                    context,
                    riskAcceptanceFor(row, state.firmwareBuild, System.currentTimeMillis()),
                )
                val accepted = row.withAcceptedRisk(
                    protectedContext = state.protectedContext,
                    // A freshly reviewed component starts unticked, which under
                    // either method means "leave it exactly as it is today".
                    effectivelyAllowed = !allowSelected,
                )
                state = state.copy(
                    rows = state.rows.map { if (it.packageName == row.packageName) accepted else it },
                )
                riskRow = null
            },
        )
    }

    if (confirmingSave) {
        SaveConfirmationDialog(
            systemCount = adminSelectedSystem.size,
            onDismiss = { confirmingSave = false },
            onConfirm = {
                confirmingSave = false
                onSave(
                    adminSelectedSystem,
                    persistedSelection(state.rows, state.ticked, adminSelectedSystem),
                    managedPackagesToPersist(state.rows),
                )
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CategoryFilters(selected: Category, onSelect: (Category) -> Unit) {
    // A horizontally scrolling row rather than a wrapping grid: the chips keep one
    // reading order, and `horizontalScroll` starts from the leading edge in both
    // layout directions, so Hebrew begins at the right without any mirroring here.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Category.values().forEach { entry ->
            FilterChip(
                selected = entry == selected,
                onClick = { onSelect(entry) },
                label = { Text(stringResource(categoryLabelOf(entry))) },
            )
        }
    }
}

private fun categoryLabelOf(category: Category): Int = when (category) {
    Category.ALL -> R.string.sysinv_filter_all
    Category.USER -> R.string.sysinv_filter_user
    Category.SYSTEM -> R.string.sysinv_filter_system
    Category.STORE -> R.string.sysinv_filter_store
    Category.BROWSER -> R.string.sysinv_filter_browser
    Category.SOCIAL -> R.string.sysinv_filter_social
    Category.MANAGEMENT -> R.string.sysinv_filter_management
    Category.PROTECTED -> R.string.sysinv_filter_protected
}

private fun stateLabelOf(state: RowState): Int = when (state) {
    RowState.ALLOWED -> R.string.sysinv_state_allowed
    RowState.BLOCKED -> R.string.sysinv_state_blocked
    RowState.PROTECTED -> R.string.sysinv_state_protected
}

private fun originLabelOf(origin: Origin): Int = when (origin) {
    Origin.USER -> R.string.sysinv_origin_user
    Origin.SYSTEM -> R.string.sysinv_origin_system
    Origin.UPDATED_SYSTEM -> R.string.sysinv_origin_updated_system
}

private fun reasonLabelOf(reason: ReasonKey): Int = when (reason) {
    ReasonKey.PROTECTED_DEVICE_GUARD -> R.string.sysinv_reason_device_guard
    ReasonKey.PROTECTED_ESSENTIAL_SYSTEM -> R.string.sysinv_reason_essential_system
    ReasonKey.PROTECTED_MANAGEMENT_TRANSPORT -> R.string.sysinv_reason_management
    ReasonKey.PROTECTED_ACTIVE_INPUT_METHOD -> R.string.sysinv_reason_active_input_method
    ReasonKey.PROTECTED_ACTIVE_WEBVIEW_PROVIDER -> R.string.sysinv_reason_active_webview
    ReasonKey.ALWAYS_BLOCKED_CATALOG -> R.string.sysinv_reason_always_blocked
    ReasonKey.KIOSK_ESCAPE_SURFACE -> R.string.sysinv_reason_kiosk_escape
    ReasonKey.KNOWN_BROWSER_OR_SOCIAL_CATALOG -> R.string.sysinv_reason_known_catalog
    ReasonKey.KNOWN_MANAGEABLE_SYSTEM -> R.string.sysinv_reason_known_manageable
    ReasonKey.UNCLASSIFIED_OEM_NEEDS_RISK_ACCEPTANCE -> R.string.sysinv_reason_unclassified_oem
    ReasonKey.UNCLASSIFIED_OEM_RISK_DRIFTED -> R.string.sysinv_reason_unclassified_oem_drift
    ReasonKey.UNCLASSIFIED_OEM_RISK_ACCEPTED -> R.string.sysinv_reason_unclassified_oem_accepted
    ReasonKey.ORDINARY_APP -> R.string.sysinv_reason_ordinary
}

@Composable
private fun InventoryRowItem(
    row: InventoryRow,
    ticked: Boolean,
    rowState: RowState,
    onTickedChange: (Boolean) -> Unit,
    onReview: () -> Unit,
) {
    val stateText = stringResource(stateLabelOf(rowState))
    val originText = stringResource(originLabelOf(row.classification.origin))
    val installText = stringResource(
        when {
            row.snapshot.hiddenByPolicy -> R.string.sysinv_hidden_by_policy
            row.snapshot.installed -> R.string.sysinv_installed
            else -> R.string.sysinv_not_installed
        },
    )
    val description = stringResource(
        R.string.sysinv_row_description,
        row.label,
        row.packageName,
        stateText,
        originText,
    )

    val base = Modifier
        .fillMaxWidth()
        .heightIn(min = 72.dp)
    Row(
        modifier = (
            if (row.toggleable) {
                base.toggleable(value = ticked, role = Role.Checkbox, onValueChange = onTickedChange)
            } else {
                base
            }
            )
            .semantics(mergeDescendants = true) { contentDescription = description }
            .padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Start,
    ) {
        AppIcon(row.packageName)
        Spacer(Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                // A third-party label can be in any language, so it is isolated
                // without forcing a direction and is allowed a second line at
                // large font scales.
                text = row.label.bidiIsolated(),
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                // Package names are Latin identifiers that may sit inside a
                // right-to-left paragraph, so they are isolated left-to-right to
                // keep the dot-separated segments in order.
                text = row.packageName.ltrIsolated(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(4.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StateBadge(rowState, stateText)
                Text(
                    text = "$originText · $installText",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = stringResource(reasonLabelOf(row.classification.reasonKey)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            if (row.needsRiskAcceptance) {
                TextButton(onClick = onReview, modifier = Modifier.padding(top = 2.dp)) {
                    Icon(
                        imageVector = Icons.Rounded.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.size(6.dp))
                    Text(
                        text = stringResource(R.string.sysinv_risk_action),
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }
        }
        Spacer(Modifier.size(12.dp))
        if (row.toggleable) {
            Checkbox(checked = ticked, onCheckedChange = null)
        } else {
            // A padlock rather than a disabled checkbox: a greyed-out box reads as
            // "not yet", and this is "never from this console".
            Icon(
                imageVector = Icons.Rounded.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.outline,
                modifier = Modifier.size(20.dp),
            )
        }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
}

@Composable
private fun StateBadge(state: RowState, text: String) {
    val container = when (state) {
        RowState.ALLOWED -> MaterialTheme.colorScheme.secondaryContainer
        RowState.BLOCKED -> MaterialTheme.colorScheme.errorContainer
        RowState.PROTECTED -> MaterialTheme.colorScheme.tertiaryContainer
    }
    val content = when (state) {
        RowState.ALLOWED -> MaterialTheme.colorScheme.onSecondaryContainer
        RowState.BLOCKED -> MaterialTheme.colorScheme.onErrorContainer
        RowState.PROTECTED -> MaterialTheme.colorScheme.onTertiaryContainer
    }
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = content,
        modifier = Modifier
            .background(container, RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

/**
 * Loads one launcher icon lazily, per visible row.
 *
 * The inventory now includes every system package, so decoding the whole set up
 * front would be hundreds of bitmaps on exactly the low-end hardware this product
 * targets. `produceState` keyed on the package name means only the rows actually
 * scrolled into view pay for their icon.
 */
@Composable
private fun AppIcon(packageName: String) {
    val context = LocalContext.current
    val sizePx = with(context.resources.displayMetrics) { (ICON_SIZE_DP * density).toInt() }
    val icon by produceState<ImageBitmap?>(initialValue = null, packageName) {
        value = withContext(Dispatchers.IO) { loadIcon(context, packageName, sizePx) }
    }
    val current = icon
    if (current != null) {
        Image(
            bitmap = current,
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

/** Best-effort launcher icon; hidden or broken packages fall back to a glyph. */
private fun loadIcon(context: Context, packageName: String, sizePx: Int): ImageBitmap? = try {
    context.packageManager.getApplicationIcon(packageName)
        .toBitmap(width = sizePx, height = sizePx, config = Bitmap.Config.ARGB_8888)
        .asImageBitmap()
} catch (ignored: PackageManager.NameNotFoundException) {
    null
} catch (ignored: RuntimeException) {
    null
}

/**
 * The advanced risk acceptance for one unclassified OEM component.
 *
 * The dialog shows exactly what is being recorded — package, signer digest,
 * version, the state before the change and the firmware build — because that
 * record is what makes a later signer or version change detectable, and an
 * operator who cannot see it cannot judge it.
 */
@Composable
private fun RiskAcceptanceDialog(
    row: InventoryRow,
    firmwareBuild: String,
    onDismiss: () -> Unit,
    onAccept: () -> Unit,
) {
    val unknown = stringResource(R.string.sysinv_risk_unknown_value)
    val priorState = stringResource(
        when {
            row.snapshot.hiddenByPolicy -> R.string.sysinv_hidden_by_policy
            row.snapshot.installed -> R.string.sysinv_installed
            else -> R.string.sysinv_not_installed
        },
    )
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(imageVector = Icons.Rounded.Warning, contentDescription = null) },
        title = { Text(stringResource(R.string.sysinv_risk_title)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.sysinv_risk_body),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (row.riskStatus == RiskAcceptanceStatus.DRIFTED) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.sysinv_risk_drift_warning),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.sysinv_risk_record_intro),
                    style = MaterialTheme.typography.labelLarge,
                )
                Spacer(Modifier.height(4.dp))
                // Each value is isolated left-to-right on its own: a package name,
                // a hex digest, a version and a build fingerprint are Latin
                // identifiers sitting inside a Hebrew sentence, and an RTL
                // paragraph would otherwise reorder their punctuation.
                RecordLine(R.string.sysinv_risk_field_package, row.packageName)
                RecordLine(
                    R.string.sysinv_risk_field_signer,
                    row.signerDigest.ifEmpty { unknown },
                )
                RecordLine(R.string.sysinv_risk_field_version, row.version.ifEmpty { unknown })
                RecordLine(R.string.sysinv_risk_field_prior_state, priorState)
                RecordLine(
                    R.string.sysinv_risk_field_firmware,
                    firmwareBuild.ifEmpty { unknown },
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onAccept) {
                Text(stringResource(R.string.sysinv_risk_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.sysinv_risk_cancel))
            }
        },
    )
}

@Composable
private fun RecordLine(template: Int, value: String) {
    Text(
        text = stringResource(template, value.ltrIsolated()),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 2.dp),
    )
}

/**
 * The explicit confirmation the roadmap requires before a system selection is
 * written. It states the verification model in as many words, because a switch
 * is not proof that Android applied anything.
 */
@Composable
private fun SaveConfirmationDialog(
    systemCount: Int,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sysinv_save_confirm_title)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.sysinv_save_confirm_body),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = pluralStringResource(
                        R.plurals.sysinv_system_selected_count,
                        systemCount,
                        systemCount,
                    ),
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.sysinv_save_confirm_action))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.sysinv_save_confirm_cancel))
            }
        },
    )
}

@Composable
private fun SaveBar(systemCount: Int, enabled: Boolean, onSave: () -> Unit) {
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
                    // Hebrew inflects for one, two and many, so the counter is a
                    // plural rather than one format string.
                    text = pluralStringResource(
                        R.plurals.sysinv_system_selected_count,
                        systemCount,
                        systemCount,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                PrimaryAction(
                    text = stringResource(R.string.sysinv_save),
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
