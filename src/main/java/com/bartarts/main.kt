package com.bartarts

import com.bartarts.decryptor.AES256PKCS7PaddingDecryptor
import com.bartarts.decryptor.Decryptor
import com.bartarts.decryptor.KeyGenerator
import com.google.common.io.BaseEncoding
import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.w3c.dom.Element
import org.w3c.dom.NodeList
import java.io.File
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.OpenOption
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.system.exitProcess

/**
 * Created by bartek on 18.10.16.
 */

fun main(args: Array<String>) {

    if (args.size < 2) {
        println("Uzycie: <input xml> <output txt>")
        exitProcess(1)
    }

//    Security.addProvider(BouncyCastleProvider());
    Security.insertProviderAt(BouncyCastleProvider(), 0);

    try {
        var inputFile: File = File(args[0])
        var dbFactory = DocumentBuilderFactory.newInstance()
        var dBuilder = dbFactory.newDocumentBuilder()
        var doc = dBuilder.parse(inputFile)
        doc.documentElement?.normalize()
        var tasks: NodeList = doc.getElementsByTagName("task")

        for (it in 0..tasks.length) {
            val task = tasks.item(it)

            if(task is Element) {
                val shouldSkip = task.getAttribute("skip")
                if(shouldSkip != null && shouldSkip.compareTo("YES", true) == 0)
                    continue

                val taskName: String = task.getAttribute("name") ?: "[NO NAME]"
                val sufix: String = task.getElementsByTagName("sufix").item(0).textContent
                val iv: String = task.getElementsByTagName("iv").item(0).textContent
                val text: String = task.getElementsByTagName("text").item(0).textContent

                try {
                    decrypt(taskName, text, sufix, iv)
                } catch (e: Exception) {
                    System.err.println("Error occurred while decrypting: ${e.message}")
                    e.printStackTrace()
                }
            }

        }

    } catch (e: Exception) {
        System.err.println("Error ocurred: ${e.message}")
        e.printStackTrace()
    }
}

fun decrypt(taskName: String, text: String, sufix: String, iv: String) {
    println("-------------------------------------")
    println("Searching key for:")
    println("Task name: $taskName")
    println("Key sufix: $sufix, length: ${sufix.length}")
    println("IV: $iv")
    println("Text: $text")


    val decodedText = Base64.getDecoder().decode(text)
    val decodedSufix = BaseEncoding.base16().decode(sufix.toUpperCase())
    val decodedIv = BaseEncoding.base16().decode(iv.toUpperCase())

    val decryptor = AES256PKCS7PaddingDecryptor(32 - decodedSufix.size, decodedSufix, decodedText, decodedIv, taskName)
    decryptor.keysPerDecryptionTask = 0x8000
    decryptor.decrypt { k, m ->
        val decKey = BaseEncoding.base16().encode(k)
        val decMsg = String(m, Charsets.UTF_8);
        val outputStr = "----\nSearching key for: $taskName\nKey sufix: $sufix, length: ${sufix.length}\nIV: $iv\nText: $text\nKey prefix: $decKey\nDecrypted message: $decMsg\n----"
        println("Found key: $decKey")

        Files.write(Paths.get("$taskName.txt"), outputStr.toByteArray(Charsets.UTF_8))
    }
}
