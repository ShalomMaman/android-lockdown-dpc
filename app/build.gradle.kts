plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun String.asBuildConfigString(): String =
    "\"" + replace("\\", "\\\\").replace("\"", "\\\"") + "\""

// Keep the bench identity stable across clean builds. This throwaway signer
// is independent of both debug and the externally configured pilot signer.
val remoteTestKeystore = rootProject.file(".gradle/device-guard-remote-test.p12")
val generateRemoteTestSigner by tasks.registering(Exec::class) {
    outputs.file(remoteTestKeystore)
    onlyIf { !remoteTestKeystore.exists() }
    doFirst { remoteTestKeystore.parentFile.mkdirs() }
    commandLine(
        File(System.getProperty("java.home"), "bin/keytool"), "-genkeypair",
        "-keystore", remoteTestKeystore, "-storetype", "PKCS12",
        "-storepass", "android", "-alias", "remote-test", "-keyalg", "RSA",
        "-keysize", "2048", "-validity", "3650", "-dname", "CN=Maakeh Remote Test",
    )
}

android {
    namespace = "com.example.lockdowndpc"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.example.lockdowndpc"
        minSdk = 26
        targetSdk = 36
        // Pilot compatibility: the applicationId and the release signing config
        // below are deliberately unchanged, so this build updates the already
        // provisioned pilot device in place. Only the version identity moves.
        // Every published pilot increments this identity so Android and the
        // signed update channel can perform an in-place, replay-safe update.
        versionCode = 16
        versionName = "0.5.6"
        buildConfigField("boolean", "REMOTE_ENROLMENT_ENABLED", "false")
        // Update channels are an explicit build choice. Ordinary builds never
        // consume ambient properties or environment variables.
        buildConfigField("String", "UPDATE_MANIFEST_URL", "".asBuildConfigString())
        buildConfigField("String", "UPDATE_PUBLIC_KEY", "".asBuildConfigString())
    }

    signingConfigs {
        create("remoteTest") {
            storeFile = remoteTestKeystore
            storeType = "PKCS12"
            storePassword = "android"
            keyAlias = "remote-test"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        create("remoteTest") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
            applicationIdSuffix = ".remotetest"
            isDebuggable = false
            signingConfig = signingConfigs.getByName("remoteTest")
            buildConfigField("boolean", "REMOTE_ENROLMENT_ENABLED", "true")
            buildConfigField("String", "UPDATE_MANIFEST_URL", "".asBuildConfigString())
            buildConfigField("String", "UPDATE_PUBLIC_KEY", "".asBuildConfigString())
        }
    }

    // Local variants do not compile the remote-test transport, even before R8.
    sourceSets {
        getByName("debug").java.srcDir("src/localBuild/java")
        getByName("release").java.srcDir("src/localBuild/java")
        getByName("testDebug").java.srcDir("src/testLocalBuild/java")
        getByName("testRelease").java.srcDir("src/testLocalBuild/java")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions.unitTests {
        isIncludeAndroidResources = true
        all {
            // Robolectric's Android framework sandbox uses reflection on JDK 17.
            it.jvmArgs(listOf(
                "java.base/java.lang",
                "java.base/java.util",
                "java.base/java.io",
                "java.base/java.net",
                "java.base/java.security",
                "java.base/java.text",
                "java.base/jdk.internal.access",
                "java.desktop/java.awt.font",
                "jdk.compiler/com.sun.tools.javac.api",
            ).map { modulePackage -> "--add-opens=$modulePackage=ALL-UNNAMED" })
        }
    }
}

androidComponents {
    finalizeDsl { extension ->
        val release = extension.buildTypes.getByName("release")
        check(!release.isDebuggable && release.isMinifyEnabled && release.isShrinkResources) {
            "Release must be non-debuggable with code and resource shrinking enabled."
        }
    }
    onVariants(selector().withBuildType("release")) { variant ->
        // buildConfigFields can only be read after configuration, so check it in a task
        // that every release build of this variant runs first.
        val fields = variant.buildConfigFields
        val variantName = variant.name
        val capitalized = variantName.replaceFirstChar { it.uppercase() }
        val gateCheck = tasks.register("verify${capitalized}RemoteEnrolmentGate") {
            group = "verification"
            doLast {
                val gate = fields?.get()?.get("REMOTE_ENROLMENT_ENABLED")
                check(gate?.type == "boolean" && gate.value.toString() == "false") {
                    "$variantName must set REMOTE_ENROLMENT_ENABLED=false."
                }
            }
        }
        tasks.matching { it.name == "pre${capitalized}Build" }.configureEach { dependsOn(gateCheck) }
    }
}

tasks.matching { it.name == "validateSigningRemoteTest" }.configureEach {
    dependsOn(generateRemoteTestSigner)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.16.0")
    // Per-app display language on API 26+. AppCompatDelegate.setApplicationLocales
    // forwards to the platform LocaleManager on API 33+ and persists the choice
    // itself below that; see AndroidManifest.xml and ui/AppLocales.kt.
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
    testImplementation("org.robolectric:robolectric:4.18.1")
}

tasks.register<Exec>("verifyRemoteTestIsolation") {
    group = "verification"
    dependsOn("assembleRelease", "assembleRemoteTest")
    commandLine(
        "python3",
        rootProject.file("tools/verify_remote_test_apk.py"),
        layout.buildDirectory.file("outputs/apk/release/app-release.apk").get().asFile,
        layout.buildDirectory.file("outputs/apk/remoteTest/app-remoteTest.apk").get().asFile,
    )
}

tasks.register<Exec>("verifyReleaseHardening") {
    dependsOn("assembleRelease")
    group = "verification"
    description = "Checks the release APK manifest and compiled remote-enrolment boundary."
    commandLine(
        "python3",
        rootProject.file("tools/verify_release_apk.py"),
        layout.buildDirectory.file("outputs/apk/release/app-release.apk").get().asFile,
    )
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
