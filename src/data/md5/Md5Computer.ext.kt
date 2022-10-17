package data.md5

import java.nio.charset.Charset

fun Md5Computer.hash(message: String, charset: Charset = Charsets.UTF_8): ByteArray {
    return hash(message.toByteArray(charset))
}