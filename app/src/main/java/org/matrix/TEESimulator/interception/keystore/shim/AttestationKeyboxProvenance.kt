package org.matrix.TEESimulator.interception.keystore.shim

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.cert.Certificate
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.pki.KeyBoxManager

/** Public sidecars only: key material and the v3 serialization remain unchanged. */
object AttestationKeyboxProvenance {
    enum class State { CURRENT, STALE, UNKNOWN, UNAVAILABLE, RETIRED }
    private const val VERSION = 1
    private val directory get() = File(ConfigurationManager.CONFIG_PATH, "key_provenance")
    private data class Binding(val namespace: Long, val publicKey: String, val chain: String)
    private data class Provenance(val binding: Binding, val signerCertificate: String)

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 255)
        }

    private fun filename(id: KeyIdentifier): String =
        digest("${id.uid}:${id.alias}".toByteArray(Charsets.UTF_8))

    private fun chainDigest(chain: List<Certificate>): String {
        val md = MessageDigest.getInstance("SHA-256")
        chain.forEach {
            val bytes = it.encoded
            md.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.size).array())
            md.update(bytes)
        }
        return md.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }

    private fun binding(namespace: Long, chain: List<Certificate>): Binding {
        require(chain.isNotEmpty())
        return Binding(namespace, digest(chain.first().publicKey.encoded), chainDigest(chain))
    }

    private fun chain(info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo): List<Certificate> =
        info.response.metadata?.let { CertificateHelper.getCertificateChain(it)?.toList() }
            ?: emptyList()

    private fun activeSigners(uid: Int): Set<String> {
        val name = ConfigurationManager.getKeyboxFileForUid(uid)
        return listOfNotNull(
            KeyBoxManager.getAttestationKey(name, "EC")?.certificates?.firstOrNull(),
            KeyBoxManager.getAttestationKey(name, "RSA")?.certificates?.firstOrNull(),
        ).map { digest(it.encoded) }.toSet()
    }

    private fun readBinding(input: DataInputStream): Binding =
        Binding(input.readLong(), input.readUTF(), input.readUTF())

    private fun writeBinding(out: DataOutputStream, binding: Binding) {
        out.writeLong(binding.namespace)
        out.writeUTF(binding.publicKey)
        out.writeUTF(binding.chain)
    }

    private fun readProvenance(id: KeyIdentifier): Provenance? = runCatching {
        val file = File(directory, filename(id) + ".origin")
        if (!file.isFile || file.length() > 4096) return@runCatching null
        DataInputStream(FileInputStream(file)).use {
            require(it.readInt() == VERSION)
            Provenance(readBinding(it), it.readUTF())
        }
    }.getOrNull()

    private fun retired(id: KeyIdentifier, binding: Binding): Boolean = runCatching {
        val file = File(directory, filename(id) + ".retired")
        if (!file.isFile || file.length() > 4096) return@runCatching false
        DataInputStream(FileInputStream(file)).use {
            require(it.readInt() == VERSION)
            val stored = readBinding(it)
            stored.namespace == binding.namespace && stored.publicKey == binding.publicKey
        }
    }.getOrDefault(false)

    @Synchronized
    private fun write(id: KeyIdentifier, extension: String, body: (DataOutputStream) -> Unit) {
        check(directory.isDirectory || directory.mkdirs())
        android.system.Os.chmod(directory.absolutePath, 448)
        val file = File(directory, filename(id) + extension)
        val tmp = File.createTempFile("provenance-", ".tmp", directory)
        try {
            android.system.Os.chmod(tmp.absolutePath, 384)
            FileOutputStream(tmp).use { stream ->
                val output = DataOutputStream(stream)
                output.writeInt(VERSION)
                body(output)
                output.flush()
                stream.fd.sync()
            }
            check(tmp.renameTo(file)) { "Cannot publish provenance metadata" }
        } finally {
            tmp.delete()
        }
    }

    /** Only generated chains are labelled; a mismatch never relabels an external chain. */
    fun remember(id: KeyIdentifier, namespace: Long, chain: List<Certificate>) {
        if (chain.isEmpty()) return
        runCatching {
            val binding = binding(namespace, chain)
            val active = activeSigners(id.uid)
            val signer = chain.drop(1).map { digest(it.encoded) }.firstOrNull { it in active }
                ?: return@runCatching
            write(id, ".origin") {
                writeBinding(it, binding)
                it.writeUTF(signer)
            }
        }.onFailure { SystemLogger.warning("Cannot persist public key provenance for $id", it) }
    }

    fun state(id: KeyIdentifier, info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo): State =
        runCatching {
            if (info.secretKey != null) return@runCatching State.UNKNOWN
            val chain = chain(info)
            if (chain.isEmpty()) return@runCatching State.UNKNOWN
            val binding = binding(info.nspace, chain)
            if (retired(id, binding)) return@runCatching State.RETIRED
            val origin = readProvenance(id) ?: return@runCatching State.UNKNOWN
            if (origin.binding != binding) return@runCatching State.UNKNOWN
            val active = activeSigners(id.uid)
            if (active.isEmpty()) State.UNAVAILABLE
            else if (origin.signerCertificate in active) State.CURRENT else State.STALE
        }.getOrElse {
            SystemLogger.warning("Cannot assess keybox provenance for $id", it)
            State.UNAVAILABLE
        }

    /**
     * In-memory verdicts for the hot read path. Keyed by the live GeneratedKeyInfo instance, so a
     * regenerated or replaced key misses automatically. Nothing is persisted here: the .retired
     * sidecars stay the source of truth and the cache is rebuilt lazily after a reboot.
     */
    private val retiredVerdicts =
        java.util.concurrent.ConcurrentHashMap<
            KeyIdentifier,
            Pair<java.lang.ref.WeakReference<KeyMintSecurityLevelInterceptor.GeneratedKeyInfo>, Boolean>,
        >()

    fun isRetired(id: KeyIdentifier, info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo): Boolean {
        if (info.secretKey != null) return false
        retiredVerdicts[id]?.let { (ref, verdict) -> if (ref.get() === info) return verdict }
        val computed =
            runCatching {
                    chain(info).takeIf { it.isNotEmpty() }?.let { retired(id, binding(info.nspace, it)) }
                        ?: false
                }
                .getOrNull() ?: return false
        retiredVerdicts[id] = java.lang.ref.WeakReference(info) to computed
        return computed
    }

    fun requireCurrentSigner(id: KeyIdentifier, info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo) {
        when (state(id, info)) {
            State.STALE, State.RETIRED -> throw android.os.ServiceSpecificException(
                7, "Attestation signer requires explicit rotation: $id"
            )
            State.UNAVAILABLE -> throw android.os.ServiceSpecificException(
                -49, "Cannot validate attestation keybox for $id"
            )
            State.UNKNOWN -> SystemLogger.warning(
                "Unknown attestation provenance for $id; preserving legacy/external key"
            )
            State.CURRENT -> Unit
        }
    }

    /**
     * Explicit retirement API. The caller must first present the namespace and public-key hash
     * to the user. No key is deleted, regenerated or re-signed. Already-begun operations may finish.
     * An older v3 reader ignores this marker; rollback restores the old reader's semantics.
     */
    fun retireStaleAttestationKey(id: KeyIdentifier, namespace: Long, publicKeySha256: String): Boolean {
        val info = KeyMintSecurityLevelInterceptor.generatedKeys[id] ?: return false
        if (id !in KeyMintSecurityLevelInterceptor.attestationKeys || info.secretKey != null) return false
        val chain = chain(info)
        if (chain.isEmpty()) return false
        val binding = binding(info.nspace, chain)
        if (binding.namespace != namespace || binding.publicKey != publicKeySha256) return false
        if (state(id, info) != State.STALE) return false
        write(id, ".retired") { writeBinding(it, binding) }
        retiredVerdicts[id] = java.lang.ref.WeakReference(info) to true
        SystemLogger.info("Explicitly retired stale attestation key $id; v3 material retained")
        return true
    }

    fun publicKeySha256(info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo): String? =
        chain(info).firstOrNull()?.publicKey?.encoded?.let { digest(it) }

    fun reportRestored(id: KeyIdentifier, info: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo) {
        val status = state(id, info)
        if (status != State.CURRENT) SystemLogger.info("Restored $id: keybox provenance=$status")
    }
}
