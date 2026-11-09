package com.isthisyou.keystore

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

class KeystorePackage : BaseReactPackage() {
  override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? {
    if (name == KeystoreModule.NAME) {
      return KeystoreModule(reactContext)
    }
    return null
  }

  override fun getReactModuleInfoProvider(): ReactModuleInfoProvider {
    return ReactModuleInfoProvider {
      mapOf(
          KeystoreModule.NAME to
              ReactModuleInfo(
                  KeystoreModule.NAME,
                  KeystoreModule::class.java.name,
                  false,
                  false,
                  false,
                  false,
              ),
      )
    }
  }
}
