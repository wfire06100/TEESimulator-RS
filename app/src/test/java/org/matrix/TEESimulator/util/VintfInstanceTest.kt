package org.matrix.TEESimulator.util

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VintfInstanceTest {
    private fun versions(xml: String, level: Int): List<Int> {
        val file = File.createTempFile("vintf-test-", ".xml")
        try {
            file.writeText(xml)
            val method = AndroidDeviceUtils::class.java.getDeclaredMethod(
                "parseKeyMintVersions", File::class.java, Int::class.javaPrimitiveType)
            method.isAccessible = true
            val entries = method.invoke(AndroidDeviceUtils, file, level) as List<*>
            return entries.map {
                val entry = requireNotNull(it)
                val field = entry.javaClass.getDeclaredField("attestationVersion")
                field.isAccessible = true
                field.getInt(entry)
            }
        } finally {
            file.delete()
        }
    }
    private val tee = "<hal format='aidl'><name>android.hardware.security.keymint</name><version>5</version><fqname>IKeyMintDevice/default</fqname></hal>"
    private val strongbox = "<hal format='aidl'><name>android.hardware.security.keymint</name><version>2</version><fqname>IKeyMintDevice/strongbox</fqname></hal>"
    @Test fun `TEE and StrongBox resolve independently`() {
        val xml = "<manifest>$tee$strongbox</manifest>"
        assertEquals(listOf(500), versions(xml, 1))
        assertEquals(listOf(200), versions(xml, 2))
    }
    @Test fun `absent StrongBox does not inherit TEE declaration`() {
        assertTrue(versions("<manifest>$tee</manifest>", 2).isEmpty())
    }
}
