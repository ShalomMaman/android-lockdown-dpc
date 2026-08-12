package com.example.lockdowndpc.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.booleanResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R

/**
 * The console keeps the trustworthy blue-on-white language of the shipped build.
 * Every foreground/background pair below is at least 4.5:1, and the status
 * headline pairs are at least 5:1, so the state of the device stays readable on
 * the low quality panels these devices tend to have.
 */
private val BrandPrimary = Color(0xFF174EA6)
private val BrandPrimaryContainer = Color(0xFFDCE7FB)
private val BrandOnPrimaryContainer = Color(0xFF0B2E63)

private val LockdownColorScheme = lightColorScheme(
    primary = BrandPrimary,
    onPrimary = Color.White,
    primaryContainer = BrandPrimaryContainer,
    onPrimaryContainer = BrandOnPrimaryContainer,
    secondary = Color(0xFF44566E),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE0E7F0),
    onSecondaryContainer = Color(0xFF1E2A38),
    tertiary = Color(0xFF2C6B4F),
    onTertiary = Color.White,
    background = Color(0xFFF6F8FC),
    onBackground = Color(0xFF191E26),
    surface = Color.White,
    onSurface = Color(0xFF191E26),
    surfaceVariant = Color(0xFFE6EBF2),
    onSurfaceVariant = Color(0xFF464E5C),
    outline = Color(0xFF6E7889),
    outlineVariant = Color(0xFFC8D0DC),
    error = Color(0xFFB02025),
    onError = Color.White,
    errorContainer = Color(0xFFFBE3E4),
    onErrorContainer = Color(0xFF5E1013),
)

/** Semantic colours for the policy status card; not part of the Material role set. */
object LockdownStatusColors {
    val verifiedContainer = Color(0xFFE2F2E7)
    val onVerifiedContainer = Color(0xFF12502F)
    val applyingContainer = Color(0xFFFDF0D8)
    val onApplyingContainer = Color(0xFF6F4400)
    val failedContainer = Color(0xFFFBE3E4)
    val onFailedContainer = Color(0xFF8A181C)
    val inactiveContainer = Color(0xFFE9EDF4)
    val onInactiveContainer = Color(0xFF3B4553)
}

private val LockdownShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(20.dp),
)

private val LockdownTypography = Typography().let { base ->
    base.copy(
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.Bold),
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.Bold),
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelLarge = base.labelLarge.copy(fontWeight = FontWeight.SemiBold),
    )
}

/**
 * The layout direction follows the *resolved strings*, not the system locale.
 *
 * Compose seeds `LocalLayoutDirection` from the activity configuration, which
 * reports RTL for any right-to-left system locale. Device Guard ships two
 * translations, so a device set to a third right-to-left language with the
 * display language left on "System default" resolved English strings into a fully
 * mirrored layout — including the auto-mirrored back arrow and the side the kiosk
 * recovery note points at. `R.bool.use_rtl_layout` is answered by the same
 * resource folder the strings came from, so text and layout can no longer
 * disagree: Hebrew mirrors, everything else does not.
 *
 * Screens that host a single left-to-right value still override the direction
 * locally; nothing below this point forces a direction globally.
 */
@Composable
fun LockdownTheme(content: @Composable () -> Unit) {
    val direction = if (booleanResource(R.bool.use_rtl_layout)) {
        LayoutDirection.Rtl
    } else {
        LayoutDirection.Ltr
    }
    CompositionLocalProvider(LocalLayoutDirection provides direction) {
        MaterialTheme(
            colorScheme = LockdownColorScheme,
            typography = LockdownTypography,
            shapes = LockdownShapes,
            content = content,
        )
    }
}
