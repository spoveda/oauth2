package oauth2.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "oauth2")
data class OAuth2Properties(
    val paths: Map<String, String>? = null,
    val issuers: Map<String, String>? = null,
    val audiences: Map<String, String>? = null,
    val scopes: Map<String, String>? = null,
    val cacheDurationInSeconds: Int = 70000
)