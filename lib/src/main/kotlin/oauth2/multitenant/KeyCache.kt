package oauth2.multitenant

import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import oauth2.multitenant.utils.KeySelectorUtils
import java.time.Duration
import java.time.Instant
import java.util.*

class KeyCache(private val issuer: String, keySelectorUtils: KeySelectorUtils, cacheDurationInSeconds: Int) {
    private var timer: Timer? = null
    private var created: Instant? = null
    lateinit var value: JWSKeySelector<SecurityContext>
    private val keySelectorUtils: KeySelectorUtils
    private val cacheDurationInSeconds: Int
    val isValid: Boolean
        get() = Duration.between(created, Instant.now()).seconds < cacheDurationInSeconds

    private fun setup() {
        generateKey()
        startRefreshJWKSTimer()
    }

    private fun generateKey() {
        val newKey = keySelectorUtils.getKey(issuer)
        if (value != newKey) {
            value = newKey
            created = Instant.now()
        }
    }

    private fun startRefreshJWKSTimer() {
        val period = 300000L // 5 minutes
        timer = Timer("Check validity jwks", true)
        val task: TimerTask = object : TimerTask() {
            override fun run() {
                generateKey()
            }
        }
        timer!!.scheduleAtFixedRate(task, period, period)
    }

    init {
        this.keySelectorUtils = keySelectorUtils
        this.cacheDurationInSeconds = cacheDurationInSeconds
        setup()
    }
}