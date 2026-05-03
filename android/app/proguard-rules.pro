# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the NativeBridge class
-keep class com.shushhh.app.NativeBridge { *; }

# Keep WebView JavaScript interface
-keepclassmembers class com.shushhh.app.MainActivity$ShushhhJSBridge {
    public *;
}
-keepattributes JavascriptInterface
