package ai.hai.jacs.platform

import android.app.Activity
import java.util.concurrent.CountDownLatch

/** Debug-only host for real lifecycle tests. No authentication hooks. */
class VaultRecoveryTestActivity : Activity() {
    val focused = CountDownLatch(1)
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) focused.countDown()
    }
}
