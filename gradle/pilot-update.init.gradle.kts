/*
 * Explicit, secret-free build switch for the existing pilot update channel.
 * The applied script validates and injects only committed public trust data.
 */
gradle.beforeProject {
    if (path == ":app") {
        apply(from = rootProject.file("gradle/pilot-signing.gradle"))
        afterEvaluate {
            apply(from = rootProject.file("gradle/pilot-update.gradle"))
        }
    }
}
