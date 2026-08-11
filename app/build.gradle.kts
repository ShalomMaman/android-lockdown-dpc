plugins {
    id("com.android.application")
}

android {
    namespace = "com.example.lockdowndpc"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.lockdowndpc"
        minSdk = 26
        targetSdk = 36
        versionCode = 6
        versionName = "0.3.3"
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
