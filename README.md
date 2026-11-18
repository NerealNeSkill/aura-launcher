# AURA launcher

Android TV launcher with the AURA home screen (side rail, search, Personalisation).

- Source: `launcher/` (Gradle project, Java).
- Build: GitHub Actions workflow `Build APK` publishes the APK as the `aura-latest` pre-release on every push to the working branch.
- Local build: `cd launcher && ./gradlew assembleRelease`.

Based on CleanYourTV (MIT), see LICENSE.
