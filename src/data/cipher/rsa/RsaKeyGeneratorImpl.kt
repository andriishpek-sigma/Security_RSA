package data.cipher.rsa

import java.security.KeyPairGenerator

class RsaKeyGeneratorImpl(
    private val keyIO: RsaKeyIO,
    private val size: Int,
) : RsaKeyGenerator {

    private val keyPairGenerator: KeyPairGenerator by lazy {
        KeyPairGenerator.getInstance("RSA")
    }

    override fun generateKeys(): RsaKeys {
        keyPairGenerator.initialize(size)
        val keys = keyPairGenerator.genKeyPair()
        return RsaKeys(
            keyIO.encodePublicKey(keys.public),
            keyIO.encodePrivateKey(keys.private)
        )
    }

}