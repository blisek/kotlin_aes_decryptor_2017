package com.bartarts.decryptor

/**
 * Created by bartek-pc on 23.10.2016.
 */
open class CharKeyGenerator(protected val keyLength: Int,
                        protected val alphabet: CharArray) : Iterator<CharArray> {
    protected var generatedKey : CharArray = CharArray(keyLength)
    protected var generationIterators : Array<CharIterator>
    protected var lastCycleEnd : Boolean = false;

    init {
        generationIterators = Array(keyLength, { alphabet.iterator(); })

        for(i in generatedKey.indices)
            generatedKey[i] = getNextOrZero(generationIterators[i])
    }

    override fun hasNext(): Boolean = !lastCycleEnd

    override fun next(): CharArray {
        val generatedKeyArray = generatedKey.copyOf()
        overrideOrShift(0)
        return generatedKeyArray
    }

    open protected fun overrideOrShift(index: Int) {
        if (index == keyLength) {
            lastCycleEnd = true
            return
        }

        val it = generationIterators[index]
        if (it.hasNext()) {
            generatedKey[index] = it.nextChar()
        } else {
            var newIterator = alphabet.iterator()
            generationIterators[index] = newIterator
            generatedKey[index] = getNextOrZero(generationIterators[index])
            overrideOrShift(index + 1)
        }

    }

    private fun getNextOrZero(it: CharIterator) : Char =
            if ( it.hasNext() ) it.nextChar() else 0.toChar()
}