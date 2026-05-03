package com.shushhh.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.util.Log;

/**
 * Manifest-registered BroadcastReceiver for USB events.
 * Handles:
 * - USB_DEVICE_ATTACHED: marks USB as connected, launches app if needed
 * - USB_DEVICE_DETACHED: triggers self-destruct via watchdog service
 * - MEDIA_REMOVED / MEDIA_EJECT: fallback for USB storage disconnect
 */
public class UsbReceiver extends BroadcastReceiver {

    private static final String TAG = "shushhh_usb";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (action == null) return;

        Log.i(TAG, "USB event received: " + action);

        switch (action) {
            case UsbManager.ACTION_USB_DEVICE_ATTACHED:
                Log.i(TAG, "USB device attached");
                UsbWatchdogService.markUsbConnected(context);
                break;

            case UsbManager.ACTION_USB_DEVICE_DETACHED:
            case Intent.ACTION_MEDIA_REMOVED:
            case Intent.ACTION_MEDIA_EJECT:
                Log.w(TAG, "USB disconnected event — forwarding to watchdog");
                // The watchdog service handles the actual self-destruct
                // If the service is running, its internal receiver handles it.
                // This receiver exists as a redundant safety net.
                try {
                    NativeBridge.nativeExecuteSelfDestruct(context.getApplicationContext());
                } catch (UnsatisfiedLinkError e) {
                    // Native library already destroyed — we're already dead
                    Log.w(TAG, "Native library unavailable (already destroyed?)");
                }
                break;
        }
    }
}
