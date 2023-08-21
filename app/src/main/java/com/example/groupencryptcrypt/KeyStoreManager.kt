package com.example.groupencryptcrypt

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeyStoreManager(private val context: Context) {

//    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
//
//    init {
//        keyStore.load(null)
//    }
//
//    fun generateKey(keyAlias: String) {
//        if (!keyStore.containsAlias(keyAlias)) {
//            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
//            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
//                keyAlias,
//                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
//            )
//                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .setRandomizedEncryptionRequired(true)
//                .build()
//
//            keyGenerator.init(keyGenParameterSpec)
//
//            // Generate and store the IV
//            val iv = SecureRandom.getSeed(12) // 12 bytes for IV
//            val ivPref = context.getSharedPreferences("IV_PREFS", Context.MODE_PRIVATE)
//            ivPref.edit().putString(keyAlias, Base64.encodeToString(iv, Base64.DEFAULT)).apply()
//
//            keyGenerator.generateKey()
//        }
//    }
//
//    fun encryptData(keyAlias: String, data: ByteArray): ByteArray {
//        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//
//        val ivPref = context.getSharedPreferences("IV_PREFS", Context.MODE_PRIVATE)
//        val ivString = ivPref.getString(keyAlias, null)
//        val iv = Base64.decode(ivString, Base64.DEFAULT)
//
//        val key = keyStore.getKey(keyAlias, null) as SecretKey
//        val spec = GCMParameterSpec(128, iv)
//
//        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
//
//        return cipher.doFinal(data)
//    }
//
//    fun decryptData(keyAlias: String, encryptedData: ByteArray): ByteArray {
//        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//
//        val ivPref = context.getSharedPreferences("IV_PREFS", Context.MODE_PRIVATE)
//        val ivString = ivPref.getString(keyAlias, null)
//        val iv = Base64.decode(ivString, Base64.DEFAULT)
//
//        val key = keyStore.getKey(keyAlias, null) as SecretKey
//        val spec = GCMParameterSpec(128, iv)
//
//        cipher.init(Cipher.DECRYPT_MODE, key, spec)
//
//        return cipher.doFinal(encryptedData)
//    }
}