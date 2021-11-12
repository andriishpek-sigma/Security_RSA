package app

import data.md5.CustomMd5Computer
import data.cipher.rc5.CustomRc5Cipher
import data.cipher.rc5.Rc5WithKeyMd5Cipher
import data.cipher.rsa.CustomRsaCipher
import data.cipher.rsa.RsaKeyGeneratorImpl
import data.cipher.rsa.RsaKeyIO
import java.io.File
import kotlin.system.measureTimeMillis

class App {

    companion object {
        private const val INPUT_FILE = "input.txt"

        private const val RC5_KEY_FILE = "rc5_key.txt"
        private const val RC5_ENCRYPTED_FILE = "rc5_encrypted.txt"
        private const val RC5_DECRYPTED_FILE = "rc5_decrypted.txt"

        private const val RSA_ENCRYPTED_FILE = "rsa_encrypted.txt"
        private const val RSA_DECRYPTED_FILE = "rsa_decrypted.txt"
    }

    private val keyIO = RsaKeyIO()

    private val rc5Cipher = Rc5WithKeyMd5Cipher(
        CustomRc5Cipher(32, 16),
        CustomMd5Computer()
    )

    private val rsaKeyGenerator = RsaKeyGeneratorImpl(keyIO, 2048)
    private val rsaCipher = CustomRsaCipher(keyIO)

    fun execute() {
        println()

        println("RC5")
        println("------------------------------------------")

        val rc5Time = measureTimeMillis {
            executeRc5()
        }

        println()
        println()

        println("RSA")
        println("------------------------------------------")

        val rsaTime = measureTimeMillis {
            executeRsa()
        }

        println()

        println("RC5 execution millis: $rc5Time")
        println("RSA execution millis: $rsaTime")

        println()

        println("RC5 faster in ${rsaTime / rc5Time} times")
    }

    private fun executeRc5() {
        val key = readFile(RC5_KEY_FILE)
        println("Key loaded: '${key.decodeToString()}'")

        val input = readFile(INPUT_FILE)
        println("Input loaded. Length: ${input.size}")

        val encrypted = rc5Cipher.encrypt(input, key)
        writeFile(RC5_ENCRYPTED_FILE, encrypted)
        println("Encrypted size: ${encrypted.size}. Saved into $RC5_ENCRYPTED_FILE")

        val decrypted = rc5Cipher.decrypt(encrypted, key)
        writeFile(RC5_DECRYPTED_FILE, decrypted)
        println("Decrypted size: ${decrypted.size}. Saved into $RC5_DECRYPTED_FILE")

        val isEqual = input.contentEquals(decrypted)
        println("Is input and decrypted data equal? ${if (isEqual) "Yes" else "No"}")
    }


    private fun executeRsa() {
        val keys = rsaKeyGenerator.generateKeys()

        val input = readFile(INPUT_FILE)
        println("Input loaded. Length: ${input.size}")

        val encrypted = rsaCipher.encrypt(input, keys.public)
        writeFile(RSA_ENCRYPTED_FILE, encrypted)
        println("Encrypted size: ${encrypted.size}. Saved into $RSA_ENCRYPTED_FILE")

        val decrypted = rsaCipher.decrypt(encrypted, keys.private)
        writeFile(RSA_DECRYPTED_FILE, decrypted)
        println("Decrypted size: ${decrypted.size}. Saved into $RSA_DECRYPTED_FILE")

        val isEqual = input.contentEquals(decrypted)
        println("Is input and decrypted data equal? ${if (isEqual) "Yes" else "No"}")
    }

    private fun readFile(name: String): ByteArray {
        return fileNameInDir(name).readBytes()
    }

    private fun writeFile(name: String, data: ByteArray) {
        return fileNameInDir(name).writeBytes(data)
    }

    private fun fileNameInDir(name: String): File {
        return File("data", name).also {
            it.parentFile.mkdirs()
            it.createNewFile()
        }
    }
}