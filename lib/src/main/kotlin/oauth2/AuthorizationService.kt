package oauth2

import oauth2.config.OAuth2Properties
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import java.util.*
import java.util.stream.Collectors

class AuthorizationService(private val properties: OAuth2Properties) {

    private fun <E> getKeyByValue(map: Map<String, String>?, value: E): String? {
        map?.forEach { (k, v) ->
            if (v == value) return k
        }
        return null
    }

    private fun hasAnyIssuer(issuersExpected: List<String>?): Boolean? {
        return issuersExpected?.any { s -> s == getIssuerFromToken() }
    }

    private fun hasAnyScope(scopesExpected: List<String>?): Boolean {
        val tokenScopes = getScopesFromToken()
        return if (tokenScopes.isEmpty()) {
            false
        } else !Collections.disjoint(tokenScopes, scopesExpected)
    }

    fun hasAnyAudience(audiencesExpected: List<String>?): Boolean {
        val tokenAudience = getAudiencesFromToken()
        return if (tokenAudience.isEmpty()) {
            false
        } else !Collections.disjoint(tokenAudience, audiencesExpected)
    }

    fun hasAnyScope(scopeExpected: String): Boolean {
        return hasAny(
            scopeExpected
        ) { scopesExpected: List<String>? ->
            hasAnyScope(
                scopesExpected
            )
        }
    }

    fun hasAnyIssuer(issuerExpected: String): Boolean {
        return hasAny(
            issuerExpected,
        ) { issuerExpected: List<String>? ->
            hasAnyIssuer(
                issuerExpected
            )
        }
    }


    private fun getAudiencesFromToken(): List<String> {
        val jwt = getJwt()
        return jwt?.audience?.mapNotNull { getKeyByValue(properties.audiences, it) } ?: emptyList()
    }

    private fun getScopesFromToken(): List<String?> {
        val jwt = getJwt()

        val scopesFromToken = jwt?.claims?.get("scope") as String
        return listOf(
            scopesFromToken.split(" ").toString().trim()
                .let { getKeyByValue(properties.scopes, it) }
                ?.takeIf { it.isNotEmpty() })
    }

    fun getClientIdFromToken(): String {
        return getClaimsFromToken()?.get("https://pomelo.la/client_id") as String
    }

    private fun getClaimsFromToken(): Map<String, Any>? {
        return getJwt()?.claims
    }

    private fun splitAndClear(listJoined: String): List<String>? {
        return Arrays.stream(listJoined.split(" ").toTypedArray()).map { obj: String -> obj.trim { it <= ' ' } }
            .collect(Collectors.toList())
    }

    private fun hasAny(from: String, of: (List<String>?) -> Boolean?): Boolean {
        return splitAndClear(from).let(of)?.or(false) ?: false
    }

    private fun getIssuerFromToken(): String? {
        return getKeyByValue(properties.issuers, getJwt().toString())
    }

    private fun getJwt(): Jwt? {
        val authentication = SecurityContextHolder.getContext().authentication
        return if (authentication == null || !authentication.isAuthenticated
            || authentication.javaClass == AnonymousAuthenticationToken::class.java
        ) {
            null
        } else authentication.principal as Jwt
    }
}