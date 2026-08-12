package com.example.lockdowndpc.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Autorenew
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.ui.theme.LockdownStatusColors

/** A single inline result line shown under the status card or a form. */
internal data class UiMessage(val text: String, val isError: Boolean)

/** Minimum touch target used for every interactive row and button. */
private val MinTouchTarget = 52.dp

/**
 * Standard page frame: a scrollable column with the blue page title, a muted
 * subtitle, and the caller's content. Matches the accepted baseline layout while
 * moving spacing and type onto the Material 3 scale.
 */
@Composable
internal fun LockdownScreen(
    title: String,
    subtitle: String,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(modifier = modifier.fillMaxSize()) { insets ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(insets)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(top = 28.dp, bottom = 36.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            content()
        }
    }
}

internal enum class StatusTone { VERIFIED, APPLYING, FAILED, INACTIVE }

private data class ToneStyle(
    val container: Color,
    val content: Color,
    val icon: ImageVector,
)

private fun toneStyleOf(tone: StatusTone): ToneStyle = when (tone) {
    StatusTone.VERIFIED -> ToneStyle(
        LockdownStatusColors.verifiedContainer,
        LockdownStatusColors.onVerifiedContainer,
        Icons.Rounded.VerifiedUser,
    )

    StatusTone.APPLYING -> ToneStyle(
        LockdownStatusColors.applyingContainer,
        LockdownStatusColors.onApplyingContainer,
        Icons.Rounded.Autorenew,
    )

    StatusTone.FAILED -> ToneStyle(
        LockdownStatusColors.failedContainer,
        LockdownStatusColors.onFailedContainer,
        Icons.Rounded.Error,
    )

    StatusTone.INACTIVE -> ToneStyle(
        LockdownStatusColors.inactiveContainer,
        LockdownStatusColors.onInactiveContainer,
        Icons.Rounded.Shield,
    )
}

/**
 * The one place an operator has to look to answer "is this device protected?".
 * [facts] carries the supporting rows (system admin, allowlist) that the old
 * three-line status block used to render as plain text.
 */
@Composable
internal fun PolicyStatusCard(
    tone: StatusTone,
    headline: String,
    facts: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
    detail: String? = null,
) {
    val style = toneStyleOf(tone)
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = style.container,
            contentColor = style.content,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = style.icon,
                    contentDescription = null,
                    modifier = Modifier.size(30.dp),
                )
                Spacer(Modifier.size(14.dp))
                Text(
                    text = headline,
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.semantics { heading() },
                )
            }
            if (detail != null) {
                Spacer(Modifier.height(10.dp))
                Text(text = detail, style = MaterialTheme.typography.bodyMedium)
            }
            if (facts.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                HorizontalDivider(color = style.content.copy(alpha = 0.20f))
                facts.forEach { (label, value) ->
                    // The label takes the leftover width so it wraps instead of
                    // colliding with the value: English labels are longer than the
                    // Hebrew ones this card was laid out for, and both grow again
                    // at large font scales. `TextAlign.End` is resolved against the
                    // layout direction, so the value stays on the trailing edge in
                    // either direction.
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            text = value,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            textAlign = TextAlign.End,
                        )
                    }
                }
            }
        }
    }
}

/** Inline success/error feedback; renders nothing when there is no message. */
@Composable
internal fun MessageBanner(message: UiMessage?, modifier: Modifier = Modifier) {
    if (message == null) return
    val container = if (message.isError) {
        LockdownStatusColors.failedContainer
    } else {
        LockdownStatusColors.verifiedContainer
    }
    val content = if (message.isError) {
        LockdownStatusColors.onFailedContainer
    } else {
        LockdownStatusColors.onVerifiedContainer
    }
    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(container, RoundedCornerShape(14.dp))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = if (message.isError) Icons.Rounded.Error else Icons.Rounded.CheckCircle,
            contentDescription = null,
            tint = content,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.size(12.dp))
        Text(
            text = message.text,
            style = MaterialTheme.typography.bodyMedium,
            color = content,
        )
    }
}

/** Numeric, masked admin PIN entry with the digit-only, max-12 filter preserved. */
@Composable
internal fun PinField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    imeAction: ImeAction = ImeAction.Next,
    onImeAction: () -> Unit = {},
) {
    OutlinedTextField(
        value = value,
        onValueChange = { onValueChange(sanitizePin(it)) },
        label = { Text(label) },
        singleLine = true,
        shape = MaterialTheme.shapes.small,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.NumberPassword,
            imeAction = imeAction,
        ),
        keyboardActions = KeyboardActions(
            onDone = { onImeAction() },
            onGo = { onImeAction() },
            onNext = { onImeAction() },
        ),
        modifier = modifier.fillMaxWidth(),
    )
}

/** Full-width primary action. There is at most one of these per screen. */
@Composable
internal fun PrimaryAction(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = MaterialTheme.shapes.small,
        contentPadding = ButtonDefaults.ContentPadding,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = MinTouchTarget),
    ) {
        if (icon != null) {
            Icon(imageVector = icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.size(10.dp))
        }
        Text(text = text, style = MaterialTheme.typography.labelLarge)
    }
}

/** Full-width, lower-emphasis action used for "cancel"-shaped choices. */
@Composable
internal fun SecondaryAction(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedButton(
        onClick = onClick,
        shape = MaterialTheme.shapes.small,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = MinTouchTarget),
    ) {
        Text(text = text, style = MaterialTheme.typography.labelLarge)
    }
}

/** A titled group of related secondary actions. */
@Composable
internal fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .padding(start = 4.dp, end = 4.dp, bottom = 8.dp)
                .semantics { heading() },
        )
        Card(
            shape = MaterialTheme.shapes.medium,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(content = content)
        }
    }
}

/** One tappable row inside a [SectionCard]. */
@Composable
internal fun ActionRow(
    icon: ImageVector,
    title: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    showDivider: Boolean = false,
    enabled: Boolean = true,
) {
    if (showDivider) {
        HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant,
            modifier = Modifier.padding(start = 56.dp),
        )
    }
    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .alpha(if (enabled) 1f else 0.62f)
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp),
        )
        Spacer(Modifier.size(16.dp))
        // `weight` rather than `fillMaxWidth`: filling the row's max width pushes
        // the text past the trailing edge instead of wrapping it, which the longer
        // English titles and large font scales both hit.
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (supporting != null) {
                Text(
                    text = supporting,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
