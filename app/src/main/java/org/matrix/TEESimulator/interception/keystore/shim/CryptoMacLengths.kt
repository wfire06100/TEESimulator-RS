package org.matrix.TEESimulator.interception.keystore.shim

internal object CryptoMacLengths {
    fun valid(bits: Int, minimum: Int, maximum: Int): Boolean =
        bits > 0 && bits % 8 == 0 && bits >= minimum && bits <= maximum
}
