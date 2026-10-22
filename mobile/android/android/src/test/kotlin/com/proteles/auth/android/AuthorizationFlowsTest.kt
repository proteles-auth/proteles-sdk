package com.proteles.auth.android

import android.content.ActivityNotFoundException
import com.proteles.auth.ProtelesException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The browser hop's outcomes, off-device: what the hop raises when no browser
 * can take the sign-in page (§10.7), when the user closes it, and when the
 * redirect arrives. Starting the Custom Tab itself runs on a device (OnDeviceTest).
 */
class AuthorizationFlowsTest {
    private fun <T> withFlow(block: suspend (AuthorizationFlows.Flow) -> T): T {
        val flow = AuthorizationFlows.start("https://auth.example.test/oauth/authorize?state=s")
        try {
            return runBlocking { block(flow) }
        } finally {
            AuthorizationFlows.finish(flow.id)
        }
    }

    @Test
    fun `no browser to open is BrowserUnavailable, raised by the hop`() = withFlow { flow ->
        assertFalse(AuthorizationFlows.launch(flow) { throw ActivityNotFoundException("no browser is installed") })
        try {
            AuthorizationFlows.await(flow)
            fail("the hop returned without a browser")
        } catch (e: ProtelesException.BrowserUnavailable) {
            // expected
        }
    }

    @Test
    fun `a browser that refuses to start is BrowserUnavailable too`() = withFlow { flow ->
        assertFalse(AuthorizationFlows.launch(flow) { throw SecurityException("not exported") })
        try {
            AuthorizationFlows.await(flow)
            fail("the hop returned without a browser")
        } catch (e: ProtelesException.BrowserUnavailable) {
            // expected
        }
    }

    @Test
    fun `an opened browser leaves the flow waiting for its redirect, or its dismissal`() {
        withFlow { flow ->
            assertTrue(AuthorizationFlows.launch(flow) { })
            assertFalse("nothing decided yet", flow.outcome.isCompleted)
            flow.outcome.complete(AuthorizationFlows.Outcome.Redirect("https://app.example.com/cb?code=c&state=s"))
            assertEquals("https://app.example.com/cb?code=c&state=s", AuthorizationFlows.await(flow))
        }
        withFlow { flow ->
            assertTrue(AuthorizationFlows.launch(flow) { })
            flow.outcome.complete(AuthorizationFlows.Outcome.Dismissed)
            try {
                AuthorizationFlows.await(flow)
                fail("a dismissed browser returned")
            } catch (e: ProtelesException.Cancelled) {
                // expected: the user closed the browser, which is not a failure
            }
        }
    }
}
