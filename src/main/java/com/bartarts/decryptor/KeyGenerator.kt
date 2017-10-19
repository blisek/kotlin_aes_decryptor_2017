package com.bartarts.decryptor

import java.io.Reader
import java.io.Writer
import java.util.*

/**
 * Created by bartek on 21.10.16.
 */
open class KeyGenerator(protected val keyLength: Int,
                   protected val alphabet: ByteArray) : Iterator<ByteArray> {
    protected var generatedKey : ByteArray = ByteArray(keyLength)
    protected var generationIterators : Array<ByteIterator>
    protected var lastCycleEnd : Boolean = false;

    init {
        generationIterators = Array(keyLength, { alphabet.iterator(); })

        for(i in generatedKey.indices)
            generatedKey[i] = getNextOrZero(generationIterators[i])
    }

    override fun hasNext(): Boolean = !lastCycleEnd

    override fun next(): ByteArray {
        val generatedKeyArray = generatedKey.copyOf()
        overrideOrShift(0)
        return generatedKeyArray
    }

    open fun saveState(writer: Writer): Boolean {
        throw NotImplementedError("KeyGenerator.saveState")
    }

    open fun loadState(reader: Reader): Boolean {
        throw NotImplementedError("KeyGenerator.loadState")
    }

    open protected fun overrideOrShift(index: Int) {
        if (index == keyLength) {
            lastCycleEnd = true
            return
        }

        val it = generationIterators[index]
        if (it.hasNext()) {
            generatedKey[index] = it.nextByte()
        } else {
            var newIterator = alphabet.iterator()
            generationIterators[index] = newIterator
            generatedKey[index] = getNextOrZero(generationIterators[index])
            overrideOrShift(index + 1)
        }

    }

    private fun getNextOrZero(it: ByteIterator) : Byte =
            if ( it.hasNext() ) it.nextByte() else 0
}