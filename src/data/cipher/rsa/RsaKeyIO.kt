package data.cipher.rsa

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class RsaKeyIO {

    private val keyFactory: KeyFactory by lazy {
        KeyFactory.getInstance("RSA")
    }

    fun decodePublicKey(key: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(key)
        return keyFactory.generatePublic(keySpec)
    }

    fun decodePrivateKey(key: ByteArray): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(key)
        return keyFactory.generatePrivate(keySpec)
    }

    fun encodePublicKey(key: PublicKey): ByteArray {
        return key.encoded
    }

    fun encodePrivateKey(key: PrivateKey): ByteArray {
        return key.encoded
    }

}