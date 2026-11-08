package com.alaabd.wifisecuritylab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RouterProfilesTest {
    @Test fun identifiesKnownNetisNc21() {
        val profile = findRouterProfile("NETIS NC21 HW V2")
        assertEquals("NETIS", profile?.vendor)
        assertEquals("NC21", profile?.model)
    }

    @Test fun identifiesRouterFamiliesConservatively() {
        assertEquals("Archer series", findRouterProfile("TP-Link Archer C6")?.model)
        assertEquals("DIR series", findRouterProfile("D-Link DIR-615")?.model)
    }

    @Test fun doesNotGuessUnknownModels() {
        assertNull(findRouterProfile("Unknown Router XYZ 9000"))
        assertNull(findRouterProfile("   "))
    }
}
