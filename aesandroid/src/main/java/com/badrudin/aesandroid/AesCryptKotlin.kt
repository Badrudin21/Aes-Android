package com.badrudin.aesandroid

import android.util.Base64
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AesCryptKotlin {
    private val CIPHER_NAME = "AES/CBC/PKCS5PADDING"
    private val CIPHER_KEY_LEN = 16 //128 bits

    fun encrypt(key: String, iv: String, data: String, encryptOnly: Boolean): String? {
        var key = key
        var iv = iv
        try {
            if (key.length < CIPHER_KEY_LEN) {
                val numPad = CIPHER_KEY_LEN - key.length

                val keyBuilder = StringBuilder(key)
                for (i in 0 until numPad) {
                    keyBuilder.append("0") //0 pad to len 16 bytes
                }
                key = keyBuilder.toString()

            } else if (key.length > CIPHER_KEY_LEN) {
                key = key.substring(0, CIPHER_KEY_LEN) //truncate to 16 bytes
            }

            if (iv.length < CIPHER_KEY_LEN) {
                val numPad = CIPHER_KEY_LEN - iv.length

                val ivBuilder = StringBuilder(iv)
                for (i in 0 until numPad) {
                    ivBuilder.append("0") //0 pad to len 16 bytes
                }
                iv = ivBuilder.toString()

            } else if (iv.length > CIPHER_KEY_LEN) {
                iv = iv.substring(0, CIPHER_KEY_LEN) //truncate to 16 bytes
            }

            val initVector = IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))
            val sKeySpec = SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "AES")

            val cipher = Cipher.getInstance(CIPHER_NAME)
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, initVector)

            val encryptedData = cipher.doFinal(data.toByteArray())

            val base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.DEFAULT)
            val base64_IV =
                Base64.encodeToString(iv.toByteArray(StandardCharsets.UTF_8), Base64.DEFAULT)

            return if (encryptOnly)
                base64_EncryptedData
            else
                "$base64_EncryptedData:$base64_IV"

        } catch (ex: Exception) {
            ex.printStackTrace()
        }

        return null
    }

    fun decrypt(key: String, data: String): String? {
        if (key.length == 16) {
            try {
                val parts = data.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                val iv = IvParameterSpec(Base64.decode(parts[1], Base64.DEFAULT))

                val sKeySpec = SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "AES")

                val cipher = Cipher.getInstance(CIPHER_NAME)
                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv)

                val decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT)

                val original = cipher.doFinal(decodedEncryptedData)
                return String(original)
            } catch (ex: Exception) {
                ex.printStackTrace()
            }

            return null
        }
        return null
    }

    fun decrypt(key: String, iv: String, data: String): String? {
        var iv = iv
        if (key.length == CIPHER_KEY_LEN) {
            try {
                val parts = data.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

                if (iv.length < CIPHER_KEY_LEN) {
                    val numPad = CIPHER_KEY_LEN - iv.length

                    val ivBuilder = StringBuilder(iv)
                    for (i in 0 until numPad) {
                        ivBuilder.append("0") //0 pad to len 16 bytes
                    }
                    iv = ivBuilder.toString()

                } else if (iv.length > CIPHER_KEY_LEN) {
                    iv = iv.substring(0, CIPHER_KEY_LEN) //truncate to 16 bytes
                }

                val initVector = IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))

                val sKeySpec = SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "AES")

                val cipher = Cipher.getInstance(CIPHER_NAME)

                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, initVector)
                val decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT)

                val original = cipher.doFinal(decodedEncryptedData)
                return String(original)
            } catch (ex: Exception) {
                ex.printStackTrace()
                return null
            }

        }
        return null
    }
}