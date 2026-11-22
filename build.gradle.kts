buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        val kotlinVersion = "2.4.21"
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
        classpath("org.jetbrains.kotlin:compose-compiler-gradle-plugin:$kotlinVersion")
    }
}

plugins {
    id("com.android.application") version "9.3.2" apply false
}
