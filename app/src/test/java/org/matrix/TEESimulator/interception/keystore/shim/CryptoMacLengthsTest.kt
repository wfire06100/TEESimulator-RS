package org.matrix.TEESimulator.interception.keystore.shim

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoMacLengthsTest {
    @Test fun rejectsInvalidMacLengths() {
        for (bits in listOf(-8, 0, 1, 63, 65, 257, 264)) {
            assertFalse(CryptoMacLengths.valid(bits, 64, 256))
        }
        assertTrue(CryptoMacLengths.valid(64, 64, 256))
        assertTrue(CryptoMacLengths.valid(256, 64, 256))
    }
    @Test fun validatesGcmTags() {
        for (bits in listOf(96, 104, 112, 120, 128)) {
            assertTrue(CryptoMacLengths.valid(bits, 96, 128))
        }
        for (bits in listOf(0, 64, 95, 97, 136)) {
            assertFalse(CryptoMacLengths.valid(bits, 96, 128))
        }
    }
}
