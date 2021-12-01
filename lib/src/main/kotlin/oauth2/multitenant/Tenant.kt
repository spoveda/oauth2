package oauth2.multitenant

data class Tenant(val issuer: String? = null, var keyCache: KeyCache)