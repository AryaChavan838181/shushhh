package com.shushhh.app;

import android.content.Context;
import android.content.res.AssetManager;

/**
 * JNI bridge to the native C++ crypto core.
 * All security-critical operations happen in native code.
 */
public class NativeBridge {

    static {
        System.loadLibrary("shushhh_native");
    }

    // ── Crypto Init ──
    public static native boolean nativeCryptoInit();

    // ── Server Configuration ──
    public static native void nativeSetServerUrls(String keyServer, String msgServer);

    // ── Tor Management ──
    public static native boolean nativeSetupTor(Context context, AssetManager assetManager);
    public static native boolean nativeLaunchTor();
    public static native boolean nativeIsTorRunning();
    public static native String nativeGetTorIp();

    // ── Authentication ──
    public static native boolean nativeRegister(String username, String password);
    public static native boolean nativeLogin(String username, String password, String filesDir);

    // ── Session Management ──
    // Returns JSON: {"status":"ok"} or {"error":"..."}
    public static native String nativeConnect(String peerUsername);

    // ── Messaging ──
    public static native boolean nativeSendMessage(String message);

    // Returns JSON array of chat messages
    public static native String nativeGetMessages();

    // Returns JSON state object
    public static native String nativeGetState();

    // ── Self Destruct ──
    public static native void nativeExecuteSelfDestruct(Context context);

    // ── Cleanup ──
    public static native void nativeCleanup();
}
