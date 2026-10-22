package com.proteles.auth.android

import com.proteles.auth.android.Browsers.Choice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Which browser shows the sign-in page. The PackageManager queries that feed it
 * run on a device (OnDeviceTest); the choice itself is decided here.
 */
class BrowsersTest {
    private val chrome = "com.android.chrome"
    private val firefox = "org.mozilla.firefox"
    private val plainBrowser = "net.example.plainbrowser" // no Custom Tabs service
    private val other = "net.example.other"

    private fun choose(default: String?, browsers: List<String>, customTabs: Set<String> = setOf(chrome, firefox)) =
        Browsers.choose(default, browsers) { it in customTabs }

    @Test
    fun `the default browser's Custom Tab, when it offers one`() {
        assertEquals(Choice.CustomTab(firefox), choose(firefox, listOf(chrome, firefox)))
    }

    @Test
    fun `another installed browser's Custom Tab, when the default offers none`() {
        assertEquals(Choice.CustomTab(chrome), choose(plainBrowser, listOf(plainBrowser, chrome)))
    }

    @Test
    fun `a Custom Tab even when no default browser is set`() {
        // resolveActivity answers with the chooser ("android"), which defaultBrowser() turns into null.
        assertEquals(Choice.CustomTab(chrome), choose(null, listOf(plainBrowser, chrome)))
    }

    @Test
    fun `with no Custom Tabs anywhere, the default browser, pinned`() {
        assertEquals(Choice.Plain(plainBrowser), choose(plainBrowser, listOf(other, plainBrowser), customTabs = emptySet()))
    }

    @Test
    fun `with no default and no Custom Tabs, the first browser - still pinned, never left to the resolver`() {
        assertEquals(Choice.Plain(other), choose(null, listOf(other, plainBrowser), customTabs = emptySet()))
    }

    @Test
    fun `a default that is not an installed full browser is never used`() {
        // e.g. an app that claims https links for one domain and also exports a Custom Tabs service
        val claimant = "com.example.applink"
        assertEquals(Choice.Plain(plainBrowser), choose(claimant, listOf(plainBrowser), customTabs = setOf(claimant)))
    }

    @Test
    fun `no browser, no choice`() {
        assertNull(choose(null, emptyList()))
    }
}
