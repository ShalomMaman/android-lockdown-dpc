/*
 * Explicit opt-in for a production build without changing the pilot build.
 * Registering the hook before project evaluation lets this override the pilot
 * defaults after app/build.gradle.kts has been evaluated.
 */
gradle.beforeProject {
    if (path == ":app") {
        afterEvaluate {
            apply(from = rootProject.file("gradle/production-identity.gradle"))
        }
    }
}
