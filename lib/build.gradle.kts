plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.4.31"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // This dependency is used internally, and not exposed to consumers on their own compile classpath.
    implementation("com.google.guava:guava:30.1-jre")
    implementation("org.springframework:spring-context:5.3.6")
    implementation("org.springframework.security:spring-security-core:5.3.12.RELEASE")
    implementation("org.springframework.security:spring-security-config:5.4.6")
    implementation("org.springframework.security:spring-security-oauth2-core:5.4.6")
    implementation("org.springframework.security:spring-security-oauth2-jose:5.4.6")

    implementation("com.nimbusds:nimbus-jose-jwt:8.3")
    implementation("org.springframework.boot:spring-boot-starter-cache:2.4.3")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")

    // This dependency is exported to consumers, that is to say found on their compile classpath.
    api("org.apache.commons:commons-math3:3.6.1")
}
