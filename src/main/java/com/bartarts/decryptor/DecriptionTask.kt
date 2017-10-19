package com.bartarts.decryptor

import com.google.common.base.Joiner
import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.charset.Charset
import java.util.concurrent.Callable
import javax.crypto.BadPaddingException
import javax.crypto.Cipher


/**
 * Created by bartek on 21.10.16.
 */

abstract class DecriptionTask(protected val keyPrefixLength: Int,
                              protected val keyByteArray: ByteArray,
                              protected val keySuffix: ByteArray,
                              protected val encryptedText: ByteArray,
                              protected val callback: (ByteArray, ByteArray) -> Unit) : Runnable {

    var usedCharset: Charset = Charsets.UTF_8
    var acceptableNonreadableCharsShare : Double = 0.2

    override fun run() {
        var decodedBytes = ByteArray(encryptedText.size + 1)
        var wroteBytes : Int = 0
        var correctKey: ByteArray? = null
        for (keyStartIndex in 0..keyByteArray.size-1 step keyPrefixLength) {
            val eng = getCipherEngine(keyByteArray, keyStartIndex, keyPrefixLength)
            try {
                wroteBytes = eng.update(encryptedText, 0, encryptedText.size, decodedBytes)
                wroteBytes += eng.doFinal(decodedBytes, wroteBytes)

                if (checkLexicalIntegrity(decodedBytes, 0, wroteBytes)) {
//                    correctKey = decodedBytes.copyOfRange(0, wroteBytes)
                    correctKey = ByteArray(keyPrefixLength, { keyByteArray[it + keyStartIndex] })
                    break
                }
            } catch (e: BadPaddingException) {}
        }
        if (correctKey != null)
            callback(correctKey, decodedBytes.copyOfRange(0, wroteBytes))

    }

    protected abstract fun getCipherEngine(key: ByteArray, offset: Int, keyPrefixLength: Int) : Cipher

    private fun checkLexicalIntegrity(text: ByteArray, offset: Int?, length: Int?) : Boolean {
        var letters = 0
        var numbers = 0
        var whitespaces = 0
        var other = 0

        val textAsString = String(text, offset ?: 0, length ?: text.size, usedCharset)
        for(char in textAsString) {

            if (char.isLetter()) {
                ++letters
            } else if (char.isDigit()) {
                ++numbers
            } else if (char.isWhitespace()) {
                ++whitespaces
            } else {
                ++other
            }

        }

        return other.toDouble() / (letters + numbers + whitespaces + other).toDouble() <= acceptableNonreadableCharsShare
    }
}