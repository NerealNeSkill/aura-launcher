# Agent guide

The app lives in `launcher/` (Java, Gradle). CI: `.github/workflows/ci.yml` (tests, lint, release build, APK under 640 KB) and `build-apk.yml` (publishes `aura-latest`). Keep the APK small and add no new permissions without a reason.
