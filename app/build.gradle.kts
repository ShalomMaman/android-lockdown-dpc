plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun String.asBuildConfigString(): String =
    "\"" + replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val updateManifestUrl = providers.gradleProperty("deviceGuardUpdateManifestUrl")
    .orElse(providers.environmentVariable("DEVICE_GUARD_UPDATE_MANIFEST_URL"))
    .orElse("")
val updatePublicKey = providers.gradleProperty("deviceGuardUpdatePublicKey")
    .orElse(providers.environmentVariable("DEVICE_GUARD_UPDATE_PUBLIC_KEY"))
    .orElse("")

android {
    namespace = "com.example.lockdowndpc"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.lockdowndpc"
        minSdk = 26
        targetSdk = 36
        versionCode = 8
        versionName = "0.4.1"
        buildConfigField("String", "UPDATE_MANIFEST_URL", updateManifestUrl.get().asBuildConfigString())
        buildConfigField("String", "UPDATE_PUBLIC_KEY", updatePublicKey.get().asBuildConfigString())
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
    testImplementation("org.json:json:20251224")
}
