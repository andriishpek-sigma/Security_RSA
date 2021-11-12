package data.cipher.rc5

interface Rc5Cipher {

    fun encrypt(data: ByteArray, keyword: ByteArray): ByteArray

    fun decrypt(data: ByteArray, keyword: ByteArray): ByteArray

}