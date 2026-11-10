package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import org.matrix.TEESimulator.attestation.KeyMintAttestation

object AuthorizeCreate {

    private const val INCOMPATIBLE_MGF_DIGEST = -78
    private const val UNSUPPORTED_MGF_DIGEST = -79
    private val supportedMgfDigests = setOf(
        Digest.SHA1,
        Digest.SHA_2_224,
        Digest.SHA_2_256,
        Digest.SHA_2_384,
        Digest.SHA_2_512,
    )

    fun check(
        keyParams: KeyMintAttestation?,
        opParams: KeyMintAttestation,
        rawOpParams: Array<KeyParameter>? = null,
    ): Int? {
        if (keyParams == null) return null
        val purpose = opParams.purpose.firstOrNull() ?: return null
        // Algorithm-level rejection runs before purpose-list check (AOSP HAL behavior)
        return checkAlgorithmPurpose(keyParams, purpose)
            ?: checkPurpose(keyParams, purpose)
            ?: checkOperationAuthorizations(keyParams, opParams)
            ?: checkTemporalValidity(keyParams, purpose)
            ?: checkCallerNonce(keyParams, purpose, rawOpParams)
    }

    private fun checkAlgorithmPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val algo = keyParams.algorithm
        if (
            (algo == Algorithm.EC || algo == Algorithm.RSA) &&
                (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT)
        ) {
            return KeystoreErrorCodes.unsupportedPurpose
        }
        if (algo == Algorithm.RSA && purpose == KeyPurpose.AGREE_KEY)
            return KeystoreErrorCodes.unsupportedPurpose
        return null
    }

    private fun checkPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        if (purpose == KeyPurpose.WRAP_KEY) return KeystoreErrorCodes.incompatiblePurpose
        if (purpose !in keyParams.purpose) return KeystoreErrorCodes.incompatiblePurpose
        return null
    }

    private fun checkOperationAuthorizations(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.blockMode.any { it !in keyParams.blockMode }) {
            return KeystoreErrorCodes.incompatibleBlockMode
        }
        if (opParams.padding.any { it !in keyParams.padding }) {
            return KeystoreErrorCodes.incompatiblePaddingMode
        }
        if (opParams.digest.any { it !in keyParams.digest }) {
            return KeystoreErrorCodes.incompatibleDigest
        }
        val isRsaOaep = keyParams.algorithm == Algorithm.RSA &&
            (opParams.padding.firstOrNull() ?: keyParams.padding.firstOrNull()) == PaddingMode.RSA_OAEP
        val requestedMgfDigests =
            if (isRsaOaep) opParams.rsaOaepMgfDigest.ifEmpty { listOf(Digest.SHA1) }
            else opParams.rsaOaepMgfDigest
        if (requestedMgfDigests.any { it !in supportedMgfDigests }) {
            return UNSUPPORTED_MGF_DIGEST
        }
        // A key with no explicit MGF authorization uses the legacy SHA-1 default.
        val authorizedMgfDigests = keyParams.rsaOaepMgfDigest.ifEmpty { listOf(Digest.SHA1) }
        if (requestedMgfDigests.any { it !in authorizedMgfDigests }) {
            return INCOMPATIBLE_MGF_DIGEST
        }

        if (keyParams.algorithm == Algorithm.AES &&
            (opParams.blockMode.firstOrNull() ?: keyParams.blockMode.firstOrNull()) == BlockMode.GCM) {
            val bits = opParams.macLength ?: return -53
            if (!CryptoMacLengths.valid(bits, maxOf(96, keyParams.minMacLength ?: 96), 128)) {
                return KeystoreErrorCodes.invalidMacLength
            }
        }

        if (
            keyParams.algorithm == Algorithm.RSA &&
                opParams.padding.contains(PaddingMode.RSA_OAEP) &&
                opParams.digest.isEmpty()
        ) {
            return KeystoreErrorCodes.incompatibleDigest
        }

        return null
    }

    private fun checkTemporalValidity(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val now = System.currentTimeMillis()

        keyParams.activeDateTime?.let { activeDate ->
            if (now < activeDate.time) return KeystoreErrorCodes.keyNotYetValid
        }

        keyParams.originationExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.ENCRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        keyParams.usageExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.DECRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        return null
    }

    private fun checkCallerNonce(
        keyParams: KeyMintAttestation,
        purpose: Int,
        rawOpParams: Array<KeyParameter>?,
    ): Int? {
        if (purpose != KeyPurpose.SIGN && purpose != KeyPurpose.ENCRYPT) return null
        if (keyParams.callerNonce == true) return null
        if (rawOpParams?.any { it.tag == Tag.NONCE } == true)
            return KeystoreErrorCodes.callerNonceProhibited
        return null
    }
}
