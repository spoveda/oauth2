package oauth2.multitenant

import java.util.concurrent.ConcurrentHashMap

class TenantRepository {
    private val tenants: MutableMap<String?, Tenant> = ConcurrentHashMap()
    fun findById(tenant: String): Tenant? {
        return tenants[tenant]
    }

    fun save(tenant: Tenant) {
        tenants[tenant.issuer] = tenant
    }
}