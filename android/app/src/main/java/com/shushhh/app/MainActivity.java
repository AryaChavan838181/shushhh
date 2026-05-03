package com.shushhh.app;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.hardware.usb.UsbManager;
import android.content.Context;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

/**
 * Main Activity hosting a full-screen WebView for the Shushhh UI.
 * All crypto operations are performed via JNI — the WebView only handles rendering.
 *
 * Flow:
 * 1. Initialize native crypto + Tor
 * 2. Start USB watchdog service
 * 3. Load WebView UI from assets/web/
 * 4. Bridge JS calls to native C++ via JavascriptInterface
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "shushhh_main";
    private WebView webView;
    private Handler refreshHandler;
    private boolean isRefreshing = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // CHECK FOR PERMANENT BRICK STATE
        java.io.File brickFlag = new java.io.File(getFilesDir(), "bricked.flag");
        if (brickFlag.exists()) {
            Log.e(TAG, "FATAL: Permanent brick flag found. App is permanently locked.");
            View blackView = new View(this);
            blackView.setBackgroundColor(0xFF000000); // Pitch black
            setContentView(blackView);
            return;
        }

        // Immersive full-screen dark mode
        setupImmersiveMode();

        // Set content view
        setContentView(R.layout.activity_main);

        // Request notification permission (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
            }
        }

        // Prevent screenshots / screen recording for security
        getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
        );

        // Keep screen on during active session
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        // Initialize WebView
        webView = findViewById(R.id.webview);
        setupWebView();

        // Initialize native layer in background
        new Thread(() -> {
            // 1. Init crypto
            boolean cryptoOk = NativeBridge.nativeCryptoInit();
            Log.i(TAG, "Crypto init: " + cryptoOk);

            // Notify crypto status immediately
            final boolean finalCryptoOk = cryptoOk;
            runOnUiThread(() -> {
                webView.evaluateJavascript(
                        "if(typeof onNativeReady === 'function') onNativeReady(" +
                                finalCryptoOk + ", false);",
                        null);
            });

            // 2. Setup Tor (extract binary from assets)
            boolean torOk = NativeBridge.nativeSetupTor(
                    getApplicationContext(), getAssets());
            Log.i(TAG, "Tor setup: " + torOk);

            // 3. Launch Tor
            if (torOk) {
                boolean torStarted = NativeBridge.nativeLaunchTor();
                Log.i(TAG, "Tor launch: " + torStarted);

                if (torStarted) {
                    // 4. Wait for Tor to bootstrap (up to 5 minutes)
                    for (int i = 0; i < 200; i++) {
                        try { Thread.sleep(1500); } catch (InterruptedException e) { break; }

                        boolean running = NativeBridge.nativeIsTorRunning();
                        Log.i(TAG, "Tor bootstrap check " + (i+1) + "/200: " + running);

                        if (running) {
                            Log.i(TAG, "Tor port 9050 is open, checking circuit...");
                            
                            // Fetch Public IP (this routes via Tor now)
                            String ip = NativeBridge.nativeGetTorIp();
                            if (ip != null && !ip.trim().isEmpty()) {
                                Log.i(TAG, "Tor circuit established! IP: " + ip);
                                
                                // Update UI with green dot and IP
                                runOnUiThread(() -> {
                                    webView.evaluateJavascript(
                                            "if(typeof updateTorIndicator === 'function') updateTorIndicator(true, '" + ip + "');",
                                            null);
                                });
                                break;
                            } else {
                                Log.i(TAG, "Tor circuit not ready yet (IP fetch failed), retrying...");
                            }
                        }
                    }
                }
            } else {
                Log.e(TAG, "Tor setup failed — binary extraction error");
            }
        }).start();

        // Start USB watchdog service
        Intent watchdogIntent = new Intent(this, UsbWatchdogService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(watchdogIntent);
        } else {
            startService(watchdogIntent);
        }

        // Setup periodic message refresh
        refreshHandler = new Handler(Looper.getMainLooper());

        Log.i(TAG, "MainActivity created");
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        // Disable text zoom for consistent layout
        settings.setTextZoom(100);

        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient());

        // Add JavaScript interface
        webView.addJavascriptInterface(new ShushhhJSBridge(), "ShushhhBridge");

        // Set dark background to prevent white flash
        webView.setBackgroundColor(0xFF0A0A0F);

        // Load the UI
        webView.loadUrl("file:///android_asset/web/index.html");
    }

    private void setupImmersiveMode() {
        WindowCompat.setDecorFitsSystemWindows(getWindow(), true);
        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        if (insetsController != null) {
            insetsController.setSystemBarsBehavior(
                    WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            insetsController.hide(WindowInsetsCompat.Type.navigationBars());
        }

        // Set status bar to dark
        if (insetsController != null) {
            insetsController.setAppearanceLightStatusBars(false);
        }
        getWindow().setStatusBarColor(0xFF0A0A0F);
        getWindow().setNavigationBarColor(0xFF0A0A0F);
    }

    @Override
    protected void onStop() {
        super.onStop();
        
        // CHECK FOR PERMANENT BRICK STATE FIRST
        java.io.File brickFlag = new java.io.File(getFilesDir(), "bricked.flag");
        if (brickFlag.exists()) {
            Log.w(TAG, "App is permanently bricked. Bypassing onStop wipe to preserve brick flag.");
            return;
        }
        
        // Conditional Ephemeral Lifecycle
        UsbManager usbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
        boolean isUsbConnected = false;
        if (usbManager != null && usbManager.getDeviceList() != null) {
            isUsbConnected = !usbManager.getDeviceList().isEmpty();
        }
        
        if (!isUsbConnected) {
            Log.w(TAG, "NO USB connected during onStop! Executing zero-persistence wipe.");
            ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                am.clearApplicationUserData();
            }
        } else {
            Log.i(TAG, "USB is connected during onStop. Retaining multi-use session.");
        }
    }

    // ── Message refresh loop ──
    private void startMessageRefresh() {
        if (isRefreshing) return;
        isRefreshing = true;

        Runnable refreshTask = new Runnable() {
            @Override
            public void run() {
                if (!isRefreshing) return;
                webView.evaluateJavascript(
                        "if(typeof refreshMessages === 'function') refreshMessages();",
                        null);
                refreshHandler.postDelayed(this, 1500);
            }
        };
        refreshHandler.postDelayed(refreshTask, 1500);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        isRefreshing = false;
        if (refreshHandler != null) {
            refreshHandler.removeCallbacksAndMessages(null);
        }
        NativeBridge.nativeCleanup();
    }

    @Override
    public void onBackPressed() {
        // Prevent accidental back navigation — require long press
        // (WebView handles its own navigation)
    }

    // ============================================================
    // JavaScript Interface — bridges WebView UI to native C++
    // ============================================================

    /**
     * Methods exposed to JavaScript via window.ShushhhBridge.*
     * All native calls are dispatched to background threads to
     * prevent UI blocking.
     */
    public class ShushhhJSBridge {

        @JavascriptInterface
        public void setServerUrls(String keyServer, String msgServer) {
            NativeBridge.nativeSetServerUrls(keyServer, msgServer);
        }

        @JavascriptInterface
        public boolean isTorRunning() {
            return NativeBridge.nativeIsTorRunning();
        }

        @JavascriptInterface
        public String register(String username, String password) {
            boolean ok = NativeBridge.nativeRegister(username, password);
            return ok ? "{\"status\":\"ok\"}" : "{\"error\":\"Registration failed\"}";
        }

        @JavascriptInterface
        public String login(String username, String password) {
            String filesDir = getFilesDir().getAbsolutePath();
            boolean ok = NativeBridge.nativeLogin(username, password, filesDir);
            if (ok) {
                runOnUiThread(() -> startMessageRefresh());
            }
            return ok ? "{\"status\":\"ok\"}" : "{\"error\":\"Login failed\"}";
        }

        @JavascriptInterface
        public String connect(String peerUsername) {
            return NativeBridge.nativeConnect(peerUsername);
        }

        @JavascriptInterface
        public boolean sendMessage(String message) {
            return NativeBridge.nativeSendMessage(message);
        }

        @JavascriptInterface
        public String getMessages() {
            return NativeBridge.nativeGetMessages();
        }

        @JavascriptInterface
        public String getState() {
            return NativeBridge.nativeGetState();
        }

        @JavascriptInterface
        public void selfDestruct() {
            NativeBridge.nativeExecuteSelfDestruct(getApplicationContext());
        }
    }
}
