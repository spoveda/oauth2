package oauth2.multitenant.utils

import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import java.net.MalformedURLException
import java.net.URL

open class KeySelectorUtils {
    companion object {
        @Volatile
        private var INSTANCE: KeySelectorUtils? = null

        fun getInstance(
        ): KeySelectorUtils =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: KeySelectorUtils(
                ).also { INSTANCE = it }
            }
    }

    fun getKey(issuer: String): JWSKeySelector<SecurityContext> {
        val jwksUri = "$issuer.well-known/jwks.json"
        var count = 0
        val maxTries = 10
        while (true) {
            try {
                return getKeyFromServer(jwksUri)
            } catch (e: KeySourceException) {
                require(++count != maxTries) { "Server oauth error." }
            } catch (e: MalformedURLException) {
                throw IllegalArgumentException("Malformed issuer url.")
            }
        }
    }

    @Throws(MalformedURLException::class, KeySourceException::class)
    protected fun getKeyFromServer(jwksUri: String?): JWSAlgorithmFamilyJWSKeySelector<SecurityContext> {
        return JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(URL(jwksUri))
    }
}