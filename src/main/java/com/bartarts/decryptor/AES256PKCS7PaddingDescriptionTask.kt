package com.bartarts.decryptor

import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Created by bartek on 22.10.16.
 */
class AES256PKCS7PaddingDescriptionTask(keyLength: Int,
                                        keyByteArray: ByteArray,
                                        keySuffix: ByteArray,
                                        encryptedText: ByteArray,
                                        callback: (ByteArray, ByteArray) -> Unit,
                                        iv: ByteArray) : DecriptionTask(keyLength, keyByteArray, keySuffix, encryptedText, callback) {

    private val ivSpec: AlgorithmParameterSpec
    private val keyBytes: ByteArray
    private val cipherEngine: Cipher

    init {
        ivSpec = IvParameterSpec(iv)
        keyBytes = ByteArray(keyPrefixLength + keySuffix.size, {
            if (it < keyPrefixLength)
                0
            else
                keySuffix[it - keyPrefixLength]
        })
        cipherEngine = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC")
    }

    override fun getCipherEngine(key: ByteArray, offset: Int, keyPrefixLength: Int): Cipher {
//        val cipherEn = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC")
        System.arraycopy(key, offset, keyBytes, 0, keyPrefixLength)
//        println("KeyBytes keyPrefixLength: ${keyBytes.size}, offset: ${offset ?: 0}, keyPrefixLength: ${keyPrefixLength ?: keyBytes.size}")
        val key = SecretKeySpec(keyBytes, 0, keyBytes.size, "AES")
        cipherEngine.init(Cipher.DECRYPT_MODE, key, ivSpec)
        return cipherEngine
    }
}