package data.cipher.rsa

interface RsaCipher {

    fun encrypt(data: ByteArray, keyword: ByteArray): ByteArray

    fun decrypt(data: ByteArray, keyword: ByteArray): ByteArray

}
