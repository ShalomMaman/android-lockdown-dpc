plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun String.asBuildConfigString(): String =
    "\"" + replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "com.example.lockdowndpc"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.lockdowndpc"
        minSdk = 26
        targetSdk = 36
        // Pilot compatibility: the applicationId and the release signing config
        // below are deliberately unchanged, so this build updates the already
        // provisioned pilot device in place. Only the version identity moves.
        // Every published pilot increments this identity so Android and the
        // signed update channel can perform an in-place, replay-safe update.
        versionCode = 14
        versionName = "0.5.4"
        // Update channels are an explicit build choice. Ordinary builds never
        // consume ambient properties or environment variables.
        buildConfigField("String", "UPDATE_MANIFEST_URL", "".asBuildConfigString())
        buildConfigField("String", "UPDATE_PUBLIC_KEY", "".asBuildConfigString())
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.04.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.16.0")
    // Per-app display language on API 26+. AppCompatDelegate.setApplicationLocales
    // forwards to the platform LocaleManager on API 33+ and persists the choice
    // itself below that; see AndroidManifest.xml and ui/AppLocales.kt.
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}

// Ordinary releases deliberately have no update channel. Keep this verification
// version-aware so a release bump never requires copying version literals into CI.
tasks.register<Exec>("verifyChannelDisabledRelease") {
    dependsOn("assembleRelease")
    group = "verification"
    description = "Verifies that the ordinary release APK has no update channel."
    commandLine(
        "python3",
        rootProject.file("tools/verify_pilot_apk.py"),
        "--apk", layout.buildDirectory.file("outputs/apk/release/app-release.apk").get().asFile,
        "--expected-package", android.defaultConfig.applicationId!!,
        "--expected-version-code", android.defaultConfig.versionCode.toString(),
        "--expected-version-name", android.defaultConfig.versionName!!,
        "--require-single-signer",
        "--expect-channel-disabled",
    )
}
