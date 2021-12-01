package oauth2.config

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector
import com.nimbusds.jwt.proc.JWTProcessor
import oauth2.multitenant.KeyCache
import oauth2.multitenant.Tenant
import oauth2.multitenant.TenantRepository
import oauth2.multitenant.utils.KeySelectorUtils
import org.springframework.boot.autoconfigure.security.oauth2.resource.IssuerUriCondition
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Conditional
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.*

/** Configures our application with Spring Security to restrict access to our API endpoints.  */
@Configuration
@EnableConfigurationProperties(OAuth2Properties::class)
@EnableWebSecurity
open class SecurityConfig : WebSecurityConfigurerAdapter() {
    private val properties: OAuth2Properties? = null

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.cors()
            .and()
            .csrf()
            .disable()
            .exceptionHandling()
            .and()
            .authorizeRequests()
            .mvcMatchers(
                properties?.paths?.get("public"),
                properties?.paths?.get("ping"),
                properties?.paths?.get("embossing")
            )
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .oauth2ResourceServer().jwt()
    }

    @Bean
    open fun inMemoryTenantRepository(): TenantRepository {
        val tenantRepository = TenantRepository()
        val issuers = properties?.issuers
        issuers?.values?.stream()
            ?.map { s ->
                Tenant(
                    issuer = s,
                    keyCache = KeyCache(s, KeySelectorUtils.getInstance(), properties.cacheDurationInSeconds)
                )
            }
            ?.forEach(tenantRepository::save)
        return tenantRepository
    }

    @Bean
    open fun jwtProcessor(
        keySelector: JWTClaimsSetAwareJWSKeySelector<SecurityContext>
    ): JWTProcessor<SecurityContext> {
        val jwtProcessor: ConfigurableJWTProcessor<SecurityContext> = DefaultJWTProcessor()
        jwtProcessor.jwtClaimsSetAwareJWSKeySelector = keySelector
        return jwtProcessor
    }

    @Bean
    @Conditional(IssuerUriCondition::class)
    open fun jwtDecoderByIssuerUri(): JwtDecoder {
        return JwtDecoders.fromIssuerLocation("lalala")
    }
}