package com.shushhh.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Log;

import androidx.core.app.NotificationCompat;

/**
 * Foreground service that monitors USB OTG connection status.
 * When the USB drive is disconnected, triggers the full self-destruct sequence.
 *
 * Uses a two-pronged approach:
 * 1. BroadcastReceiver for ACTION_USB_DEVICE_DETACHED (instant detection)
 * 2. Polling loop every 2 seconds as fallback (some devices don't fire broadcast reliably)
 */
public class UsbWatchdogService extends Service {

    private static final String TAG = "shushhh_watchdog";
    private static final String CHANNEL_ID = "shushhh_watchdog_channel";
    private static final int NOTIFICATION_ID = 1337;

    private PowerManager.WakeLock wakeLock;
    private Handler handler;
    private boolean usbWasConnected = false;
    private boolean selfDestructTriggered = false;

    // USB detach receiver
    private final BroadcastReceiver usbDetachReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Log.w(TAG, "Received broadcast: " + action);

            if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action) ||
                Intent.ACTION_MEDIA_REMOVED.equals(action) ||
                Intent.ACTION_MEDIA_EJECT.equals(action)) {

                if (usbWasConnected && !selfDestructTriggered) {
                    Log.w(TAG, "USB DISCONNECTED — initiating self-destruct");
                    triggerSelfDestruct();
                }
            }
        }
    };

    // Polling runnable (fallback for devices that don't fire USB broadcasts)
    private final Runnable usbPollRunnable = new Runnable() {
        @Override
        public void run() {
            if (selfDestructTriggered) return;

            // Check USB connection via UsbManager
            UsbManager usbManager = (UsbManager) getSystemService(USB_SERVICE);
            boolean currentlyConnected = false;

            if (usbManager != null && usbManager.getDeviceList() != null) {
                currentlyConnected = !usbManager.getDeviceList().isEmpty();
            }

            if (usbWasConnected && !currentlyConnected) {
                Log.w(TAG, "USB poll detected disconnect — initiating self-destruct");
                triggerSelfDestruct();
                return;
            }

            if (currentlyConnected) {
                usbWasConnected = true;
            }

            // Re-schedule poll
            handler.postDelayed(this, 2000);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "UsbWatchdogService created");

        createNotificationChannel();
        handler = new Handler(Looper.getMainLooper());

        // Acquire wake lock to keep polling alive
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm != null) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    "shushhh:watchdog");
            wakeLock.acquire();
        }

        // Register dynamic broadcast receivers
        IntentFilter filter = new IntentFilter();
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        filter.addAction(Intent.ACTION_MEDIA_REMOVED);
        filter.addAction(Intent.ACTION_MEDIA_EJECT);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbDetachReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbDetachReceiver, filter);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Start as foreground service with persistent notification
        Notification notification = buildNotification();
        startForeground(NOTIFICATION_ID, notification);

        // Record initial USB state
        UsbManager usbManager = (UsbManager) getSystemService(USB_SERVICE);
        if (usbManager != null && usbManager.getDeviceList() != null) {
            usbWasConnected = !usbManager.getDeviceList().isEmpty();
        }

        // Start polling loop as fallback
        handler.postDelayed(usbPollRunnable, 2000);

        Log.i(TAG, "Watchdog armed. USB connected: " + usbWasConnected);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        handler.removeCallbacks(usbPollRunnable);

        try {
            unregisterReceiver(usbDetachReceiver);
        } catch (Exception ignored) {}

        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ── Self-Destruct Trigger ──
    private void triggerSelfDestruct() {
        if (selfDestructTriggered) return;
        selfDestructTriggered = true;

        Log.w(TAG, "╔══════════════════════════════════════╗");
        Log.w(TAG, "║   USB DISCONNECTED — SELF DESTRUCT   ║");
        Log.w(TAG, "╚══════════════════════════════════════╝");

        // Execute native self-destruct (shreds files, wipes keys, clears data)
        try {
            NativeBridge.nativeExecuteSelfDestruct(getApplicationContext());
        } catch (Exception e) {
            Log.e(TAG, "Native self-destruct threw: " + e.getMessage());
            // Fallback: clear data via ActivityManager directly
            try {
                android.app.ActivityManager am = (android.app.ActivityManager)
                        getSystemService(ACTIVITY_SERVICE);
                if (am != null) {
                    am.clearApplicationUserData();
                }
            } catch (Exception e2) {
                Log.e(TAG, "Fallback clear also failed: " + e2.getMessage());
            }
        }
    }

    // ── Notification ──
    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Secure Session",
                NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("Active secure messaging session");
        channel.setShowBadge(false);

        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, mainIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("shushhh")
                .setContentText("\uD83D\uDD12 Secure session active")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .setContentIntent(pendingIntent)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    // ── Public API for marking USB connected ──
    public static void markUsbConnected(Context context) {
        // Can be called from UsbReceiver when USB is attached
        Log.i(TAG, "USB connection marked as active");
    }
}
