package com.isthisyou.keystore

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.WritableMap
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import org.json.JSONObject

/**
 * Hardware P-256 keys. StrongBox is preferred. If the device has none
 * (the development Moto G8 Plus on Android 10 does not), the key is generated
 * in the TEE and the tier is recorded on the key.
 *
 * The KSK sets user authentication required. Signing it shows BiometricPrompt.
 * The ZSK does not.
 */
class KeystoreModule(private val context: ReactApplicationContext) :
    ReactContextBaseJavaModule(context) {

  private val store: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  override fun getName(): String = NAME

  @ReactMethod
  fun hardwareInfo(promise: Promise) {
    val map = Arguments.createMap()
    map.putBoolean(
        "strongBoxAvailable",
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
    )
    promise.resolve(map)
  }

  @ReactMethod
  fun generateKey(
      alias: String,
      purpose: String,
      requireBiometric: Boolean,
      attestationChallengeBase64: String?,
      preferStrongBox: Boolean,
      promise: Promise,
  ) {
    try {
      if (store.containsAlias(alias)) {
        promise.reject("ALREADY_EXISTS", alias)
        return
      }
      val challenge = attestationChallengeBase64?.let { Base64.decode(it, Base64.DEFAULT) }
      var attestationError: String? = null
      var usedStrongBox = false
      val strongBox =
          preferStrongBox &&
              context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
      try {
        generate(alias, requireBiometric, challenge, strongBox)
        usedStrongBox = strongBox
      } catch (error: Exception) {
        if (strongBox && isStrongBoxFailure(error)) {
          generate(alias, requireBiometric, challenge, false)
          usedStrongBox = false
        } else if (challenge != null) {
          attestationError = error.message
          try {
            generate(alias, requireBiometric, null, false)
          } catch (again: Exception) {
            promise.reject("KEY_GEN_FAILED", again.message, again)
            return
          }
        } else {
          promise.reject("KEY_GEN_FAILED", error.message, error)
          return
        }
      }
      val record = describe(alias, purpose, requireBiometric, usedStrongBox, attestationError)
      saveMeta(record)
      promise.resolve(record)
    } catch (error: Exception) {
      promise.reject("KEY_GEN_FAILED", error.message, error)
    }
  }

  @ReactMethod
  fun sign(alias: String, messageBase64: String, promptTitle: String, promise: Promise) {
    try {
      val message = Base64.decode(messageBase64, Base64.DEFAULT)
      val privateKey = store.getKey(alias, null)
          ?: run {
            promise.reject("KEY_NOT_FOUND", alias)
            return
          }
      val signature = Signature.getInstance("SHA256withECDSA")
      val gated = requiresBiometric(alias)
      if (!gated) {
        signature.initSign(privateKey as java.security.PrivateKey)
        signature.update(message)
        promise.resolve(signResult(derToP1363(signature.sign()), false))
        return
      }
      val activity = context.currentActivity
      if (activity !is FragmentActivity) {
        promise.reject("NO_ACTIVITY", "BiometricPrompt needs the current activity")
        return
      }
      signature.initSign(privateKey as java.security.PrivateKey)
      val executor = ContextCompat.getMainExecutor(activity)
      val prompt =
          BiometricPrompt(
              activity,
              executor,
              object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                  try {
                    val authed = result.cryptoObject?.signature
                        ?: throw IllegalStateException("no signature")
                    authed.update(message)
                    promise.resolve(signResult(derToP1363(authed.sign()), true))
                  } catch (error: Exception) {
                    promise.reject("SIGN_FAILED", error.message, error)
                  }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                  promise.reject("BIOMETRIC_FAILED", errString.toString())
                }
              },
          )
      val info =
          BiometricPrompt.PromptInfo.Builder()
              .setTitle(if (promptTitle.isBlank()) "Confirm key use" else promptTitle)
              .setSubtitle("Biometric approval for the zone signing key")
              .setNegativeButtonText("Cancel")
              .build()
      activity.runOnUiThread {
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
      }
    } catch (error: Exception) {
      promise.reject("SIGN_FAILED", error.message, error)
    }
  }

  @ReactMethod
  fun signMany(alias: String, messages: ReadableArray, promise: Promise) {
    try {
      if (requiresBiometric(alias)) {
        promise.reject("BIOMETRIC_BATCH_REFUSED", "This key requires a biometric for each use")
        return
      }
      val privateKey = store.getKey(alias, null) as? java.security.PrivateKey
          ?: run {
            promise.reject("KEY_NOT_FOUND", alias)
            return
          }
      val out = Arguments.createArray()
      for (i in 0 until messages.size()) {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(Base64.decode(messages.getString(i), Base64.DEFAULT))
        out.pushString(Base64.encodeToString(derToP1363(signature.sign()), Base64.NO_WRAP))
      }
      promise.resolve(out)
    } catch (error: Exception) {
      promise.reject("SIGN_FAILED", error.message, error)
    }
  }

  @ReactMethod
  fun getKey(alias: String, promise: Promise) {
    promise.resolve(if (store.containsAlias(alias)) loadMeta(alias) else null)
  }

  @ReactMethod
  fun listKeys(promise: Promise) {
    val list = Arguments.createArray()
    val meta = prefs()
    for (key in meta.keys()) {
      list.pushMap(loadMeta(key))
    }
    promise.resolve(list)
  }

  @ReactMethod
  fun deleteKey(alias: String, promise: Promise) {
    if (store.containsAlias(alias)) {
      store.deleteEntry(alias)
    }
    val meta = prefs()
    meta.remove(alias)
    savePrefs(meta)
    promise.resolve(null)
  }

  @ReactMethod
  fun attest(alias: String, challengeBase64: String, promise: Promise) {
    try {
      val chain = store.getCertificateChain(alias)
      if (chain == null) {
        promise.reject("KEY_NOT_FOUND", alias)
        return
      }
      val map = Arguments.createMap()
      map.putString("alias", alias)
      map.putString("challengeBase64", challengeBase64)
      val certs = Arguments.createArray()
      for (cert in chain) {
        certs.pushString(Base64.encodeToString(cert.encoded, Base64.NO_WRAP))
      }
      map.putArray("certChainDerBase64", certs)
      map.putBoolean("simulator", false)
      promise.resolve(map)
    } catch (error: Exception) {
      promise.reject("ATTEST_FAILED", error.message, error)
    }
  }

  private fun generate(
      alias: String,
      requireBiometric: Boolean,
      challenge: ByteArray?,
      strongBox: Boolean,
  ) {
    val builder =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setCertificateSubject(X500Principal("CN=Is this you?"))
            .setUserAuthenticationRequired(requireBiometric)
    if (challenge != null) {
      builder.setAttestationChallenge(challenge)
    }
    if (strongBox) {
      builder.setIsStrongBoxBacked(true)
    }
    if (requireBiometric) {
      if (Build.VERSION.SDK_INT >= 30) {
        builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      } else {
        @Suppress("DEPRECATION")
        builder.setUserAuthenticationValidityDurationSeconds(-1)
      }
    }
    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    generator.initialize(builder.build())
    generator.generateKeyPair()
  }

  private fun describe(
      alias: String,
      purpose: String,
      requireBiometric: Boolean,
      usedStrongBox: Boolean,
      attestationError: String?,
  ): WritableMap {
    val cert = store.getCertificate(alias)
    val publicKey = cert.publicKey as ECPublicKey
    val raw = fixed32(publicKey.w.affineX) + fixed32(publicKey.w.affineY)
    val tier = tierOf(alias, usedStrongBox)
    val map = Arguments.createMap()
    map.putString("alias", alias)
    map.putString("purpose", purpose)
    map.putString("hardwareTier", tier)
    map.putBoolean("requireBiometric", requireBiometric)
    map.putString("spkiDerBase64", Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP))
    map.putString("publicRawBase64", Base64.encodeToString(raw, Base64.NO_WRAP))
    map.putDouble("createdAt", System.currentTimeMillis().toDouble())
    map.putBoolean("simulator", false)
    if (attestationError != null) {
      map.putString("attestationError", attestationError)
    }
    return map
  }

  private fun tierOf(alias: String, usedStrongBox: Boolean): String {
    return try {
      val key = store.getKey(alias, null)
      val factory = java.security.KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
      val info = factory.getKeySpec(key, KeyInfo::class.java)
      if (Build.VERSION.SDK_INT >= 31) {
        when (info.securityLevel) {
          KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
          KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
          else -> "software"
        }
      } else if (usedStrongBox && info.isInsideSecureHardware) {
        "strongbox"
      } else if (info.isInsideSecureHardware) {
        "tee"
      } else {
        "software"
      }
    } catch (_: Exception) {
      if (usedStrongBox) "strongbox" else "tee"
    }
  }

  private fun requiresBiometric(alias: String): Boolean {
    val meta = prefs().optJSONObject(alias)
    return meta?.optBoolean("requireBiometric") ?: false
  }

  private fun saveMeta(record: WritableMap) {
    val meta = prefs()
    val obj = JSONObject()
    obj.put("alias", record.getString("alias"))
    obj.put("purpose", record.getString("purpose"))
    obj.put("hardwareTier", record.getString("hardwareTier"))
    obj.put("requireBiometric", record.getBoolean("requireBiometric"))
    obj.put("spkiDerBase64", record.getString("spkiDerBase64"))
    obj.put("publicRawBase64", record.getString("publicRawBase64"))
    obj.put("createdAt", record.getDouble("createdAt"))
    meta.put(record.getString("alias")!!, obj)
    savePrefs(meta)
  }

  private fun loadMeta(alias: String): WritableMap {
    val obj = prefs().getJSONObject(alias)
    val map = Arguments.createMap()
    map.putString("alias", obj.getString("alias"))
    map.putString("purpose", obj.getString("purpose"))
    map.putString("hardwareTier", obj.getString("hardwareTier"))
    map.putBoolean("requireBiometric", obj.getBoolean("requireBiometric"))
    map.putString("spkiDerBase64", obj.getString("spkiDerBase64"))
    map.putString("publicRawBase64", obj.getString("publicRawBase64"))
    map.putDouble("createdAt", obj.getDouble("createdAt"))
    map.putBoolean("simulator", false)
    return map
  }

  private fun prefs(): JSONObject {
    val raw = context.getSharedPreferences(PREFS, 0).getString("keys", "{}") ?: "{}"
    return JSONObject(raw)
  }

  private fun savePrefs(meta: JSONObject) {
    context.getSharedPreferences(PREFS, 0).edit().putString("keys", meta.toString()).apply()
  }

  private fun signResult(raw: ByteArray, prompted: Boolean): WritableMap {
    val map = Arguments.createMap()
    map.putString("signatureBase64", Base64.encodeToString(normalizeLowS(raw), Base64.NO_WRAP))
    map.putBoolean("prompted", prompted)
    return map
  }

  private fun isStrongBoxFailure(error: Exception): Boolean {
    var current: Throwable? = error
    while (current != null) {
      if (current is StrongBoxUnavailableException) {
        return true
      }
      if (current.message?.contains("StrongBox", ignoreCase = true) == true) {
        return true
      }
      current = current.cause
    }
    return false
  }

  private fun fixed32(value: BigInteger): ByteArray {
    var raw = value.toByteArray()
    if (raw.size == 33 && raw[0] == 0.toByte()) {
      raw = raw.copyOfRange(1, 33)
    }
    if (raw.size > 32) {
      error("coordinate too long")
    }
    val out = ByteArray(32)
    System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
    return out
  }

  private fun derToP1363(der: ByteArray): ByteArray {
    var i = 2
    if (der[1].toInt() and 0x80 != 0) {
      val n = der[1].toInt() and 0x7f
      i = 2 + n
    }
    fun readInt(): ByteArray {
      if (der[i] != 0x02.toByte()) {
        error("expected integer")
      }
      i += 1
      val len = der[i].toInt() and 0xff
      i += 1
      val value = der.copyOfRange(i, i + len)
      i += len
      return value
    }
    return left32(readInt()) + left32(readInt())
  }

  private fun left32(value: ByteArray): ByteArray {
    var raw = value
    if (raw.isNotEmpty() && raw[0] == 0.toByte()) {
      raw = raw.copyOfRange(1, raw.size)
    }
    val out = ByteArray(32)
    System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
    return out
  }

  private fun normalizeLowS(sig: ByteArray): ByteArray {
    val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val half = n.shiftRight(1)
    val s = BigInteger(1, sig.copyOfRange(32, 64))
    if (s <= half) {
      return sig
    }
    return sig.copyOfRange(0, 32) + fixed32(n.subtract(s))
  }

  companion object {
    const val NAME = "IsThisYouKeystore"
    private const val PREFS = "isthisyou_keystore"
  }
}
