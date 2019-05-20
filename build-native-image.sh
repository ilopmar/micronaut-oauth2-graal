./gradlew assemble
native-image --no-server -cp build/libs/test-github-oauth-0.1.jar \
        -H:+PrintClassInitialization