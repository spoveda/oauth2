package oauth2.multitenant

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector
import oauth2.config.OAuth2Properties
import oauth2.multitenant.utils.KeySelectorUtils
import java.security.Key

class TenantJWSKeySelector(
    private val selectors: MutableMap<String, JWSKeySelector<SecurityContext>>,
    private val tenantRepository: TenantRepository,
    private val properties: OAuth2Properties,
    private val keySelectorUtils: KeySelectorUtils
) : JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

    @Throws(KeySourceException::class)
    override fun selectKeys(
        jwsHeader: JWSHeader, jwtClaimsSet: JWTClaimsSet, securityContext: SecurityContext
    ): List<Key> {
        val selected = selectors.computeIfAbsent(
            toTenant(jwtClaimsSet),
        ) { tenant: String ->
            fromTenant(
                tenant
            )
        }
        return selected.selectJWSKeys(jwsHeader, securityContext)
    }

    private fun toTenant(claimSet: JWTClaimsSet): String {
        return claimSet.getClaim("iss") as String
    }

    private fun fromTenant(tenant: String): JWSKeySelector<SecurityContext> {
        val tenantSelected = tenantRepository.findById(tenant) ?: throw IllegalArgumentException("unknown tenant")

        if (tenantSelected.keyCache.isValid) {
            return tenantSelected.keyCache.value
        }
        tenantSelected.keyCache = KeyCache(
            tenantSelected.issuer!!,
            keySelectorUtils,
            properties.cacheDurationInSeconds
        )

        return tenantSelected.keyCache.value
    }
}