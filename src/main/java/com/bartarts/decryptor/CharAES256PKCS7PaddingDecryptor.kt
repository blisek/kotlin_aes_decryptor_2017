package com.bartarts.decryptor


/**
 * Created by bartek on 21.10.16.
 */
class CharAES256PKCS7PaddingDecryptor(keyLength: Int,
                                  keySuffix: ByteArray,
                                  cipheredText: ByteArray,
                                  iv: ByteArray,
                                  taskName: String) : Decryptor(keyLength, iv, keySuffix, cipheredText, taskName) {

//    private val alphabet = byteArrayOf(
//            '0'.toByte(), '1'.toByte(), '2'.toByte(), '3'.toByte(), '4'.toByte(), '5'.toByte(), '6'.toByte(),
//            '7'.toByte(), '8'.toByte(), '9'.toByte(), 'a'.toByte(), 'b'.toByte(), 'c'.toByte(), 'd'.toByte(),
//            'e'.toByte(), 'f'.toByte()
//    )
    private val alphabet = ByteArray(256, { it.toByte() })

    override fun getKeyGenerator() : KeyGenerator = AES256PKCS7PaddingKeyGenerator(keyLength, alphabet)

}