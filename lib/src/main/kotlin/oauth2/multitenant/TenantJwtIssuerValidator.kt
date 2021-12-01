package oauth2.multitenant

import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtIssuerValidator

import java.util.*
import java.util.function.Function
import java.util.function.Predicate

class TenantJwtIssuerValidator(
    private val tenantRepository: TenantRepository,
    private val validators: MutableMap<String, JwtIssuerValidator>
) : OAuth2TokenValidator<Jwt> {
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        return validators.computeIfAbsent(
            toTenant(token)
        ) { tenant: String ->
            fromTenant(
                tenant
            )
        }.validate(token)
    }

    private fun toTenant(jwt: Jwt): String {
        return jwt.issuer.toString()
    }

    private fun fromTenant(tenant: String): JwtIssuerValidator {
        return Optional.ofNullable(tenantRepository.findById(tenant))
            .filter { it != null }
            .map { it.issuer }
            .map { JwtIssuerValidator(it) }
            .orElseThrow {
                IllegalArgumentException(
                    "unknown tenant"
                )
            }
    }
}