package com.bartarts.decryptor

import com.google.common.base.Joiner
import com.sun.org.apache.xpath.internal.operations.Bool
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Created by bartek on 18.10.16.
 */

abstract class Decryptor(protected val keyLength: Int,
                         protected val iv: ByteArray,
                         protected val keySuffix: ByteArray,
                         protected val cipheredText: ByteArray,
                         protected val taskName: String) {
    var keysPerDecryptionTask : Int = 1000
    protected val keyPrefixLength : Int = keyLength - keySuffix.size
    protected val coreQuantity : Int = Runtime.getRuntime().availableProcessors()

    private val STORED_KEY_NAME: String = "stored_key_$taskName.txt"

    // przetwarzanie zadan
    private val concurrentQueue: ArrayBlockingQueue<Runnable>
    private val workingThreads: Array<WorkingThread>
    private val executedTasks: AtomicInteger = AtomicInteger(0)
    private val keyFound: AtomicBoolean = AtomicBoolean(false)

    init {
        concurrentQueue = ArrayBlockingQueue(coreQuantity * 2)
        workingThreads = Array(coreQuantity, { val wt = WorkingThread(concurrentQueue); Thread(wt).start(); wt })
    }

    fun decrypt(callback: (ByteArray, ByteArray) -> Unit) {
        val keyGenerator = getKeyGenerator()
        var cycleCounter: Long = 0;
        var keyCounter: Int = 0;

        loadKey(keyGenerator)
        while (keyGenerator.hasNext() && !keyFound.get()) {
            val keysArray: ByteArray = ByteArray(keysPerDecryptionTask * keyLength)

            for (key in keyGenerator) {

                System.arraycopy(key, 0, keysArray, keyCounter * keyLength, keyLength)
                keyCounter = (keyCounter + 1) % keysPerDecryptionTask
                if (keyCounter == 0)
                    break
            }
            val decriptionTask: DecriptionTask =
                    AES256PKCS7PaddingDescriptionTask(keyLength, keysArray, keySuffix, cipheredText, { k, t ->  keyFound.set(true); callback(k, t) }, iv)
//            println(Joiner.on(',').join(it.toTypedArray()))
//            concurrentQueue.add(decriptionTask)
//            println("Cycle #$cycleCounter ordered.")
//            ++cycleCounter

            concurrentQueue.put(decriptionTask)

            storeKey(keyGenerator)
        }

        while (!concurrentQueue.isEmpty() && !keyFound.get())
            Thread.sleep(5000)

        for (workingThread in workingThreads)
            workingThread.started = false;

        File(STORED_KEY_NAME).delete()
    }

    private fun storeKey(keyGenerator: KeyGenerator) {
        val f: File = File(STORED_KEY_NAME)
        FileWriter(f).use {
            keyGenerator.saveState(it)
        }
    }

    private fun loadKey(keyGenerator: KeyGenerator) {
        val f: File = File(STORED_KEY_NAME)
        if (f.exists()) {
            FileReader(f).use {
                keyGenerator.loadState(it)
            }
        }
    }


    protected abstract fun getKeyGenerator() : KeyGenerator

    private inner class WorkingThread(private val tasksQueue: BlockingQueue<Runnable>) : Runnable {
        var started: Boolean = true

        override fun run() {
            while (started) {
                val task: Runnable? = tasksQueue.poll(500, TimeUnit.MILLISECONDS)
                if (task != null) {
                    executedTasks.andIncrement
                    task.run()
                    executedTasks.andDecrement
                }
            }
        }
    }
}