package com.bartarts.decryptor

import com.google.common.base.Joiner
import com.google.common.io.BaseEncoding
import com.sun.org.apache.xpath.internal.operations.Bool
import java.io.IOException
import java.io.Reader
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.*

/**
 * Created by bartek on 22.10.16.
 */
class AES256PKCS7PaddingKeyGenerator(keyLength: Int, alphabet: ByteArray) : KeyGenerator(keyLength, alphabet) {

    private val STORE_KEY_PROPERTY_NAME = "key"
    private val DATE_FORMAT_STRING = "yyyy-MM-dd HH:mm:ss"
    init {
        generatedKey = ByteArray(keyLength, { if (it % 2 == 0) 0 else -1 })
    }

    override fun overrideOrShift(index: Int) {
        if (index == keyLength) {
            lastCycleEnd = true
            return
        }

        var intValue: Int

        if (index % 2 == 0) {
            intValue = generatedKey[index] + 1
            generatedKey[index] = intValue.toByte()
            if (intValue == 0)
                overrideOrShift(index + 1)
        } else {
            intValue = generatedKey[index] - 1
            generatedKey[index] = intValue.toByte()
            if (intValue == -1)
                overrideOrShift(index + 1)
        }
    }

    override fun saveState(writer: Writer): Boolean {
        val prop: Properties = Properties()
        val base16EncodedKey: String =
                BaseEncoding.base16().encode(generatedKey)
        prop.setProperty(STORE_KEY_PROPERTY_NAME, base16EncodedKey)
        try {
            prop.store(writer, null)
            return true
        } catch(err: Exception) {
            System.err.println("Error while storing key: ${err.message}")
            err.printStackTrace()
            return false
        }
    }

    override fun loadState(reader: Reader): Boolean {
        val prop = Properties()
        try {
            prop.load(reader)
            val loadedKey = prop.getProperty(STORE_KEY_PROPERTY_NAME)
            if(loadedKey != null && (loadedKey.length / 2) == keyLength) {
                generatedKey = BaseEncoding.base16().decode(loadedKey).copyOf()
                println("Stored key loaded")
                return true
            } else {
                System.err.println("Key missing or invalid key length")
            }
        } catch(err: Exception) {
            System.err.println("Error while loading key: ${err.message}")
            err.printStackTrace()
        }

        return false
    }
}