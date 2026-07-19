import time
import wmi
from core.logger import write_log


def run(session):
    """
    Watch for USB device connections using WMI.
    Uses Win32_USBHub (your original) for device name/ID,
    with a fallback to Win32_USBControllerDevice.
    Requires admin privileges.
    """
    print("[USBMonitor] Monitoring USB device connections...")

    try:
        c       = wmi.WMI()
        watcher = c.Win32_USBHub.watch_for("creation")

        while True:
            try:
                usb = watcher()
                data = {
                    "device_name": getattr(usb, "Name", "unknown"),
                    "device_id"  : getattr(usb, "DeviceID", "unknown"),
                }
                write_log("usb_connected", data, "usb")

            except Exception:
                time.sleep(5)

    except Exception as e:
        # Fallback: Win32_USBControllerDevice (less detail but always works)
        print(f"[USBMonitor] Win32_USBHub unavailable ({e}), using fallback watcher...")
        try:
            c       = wmi.WMI()
            watcher = c.watch_for(
                notification_type="Creation",
                wmi_class="Win32_USBControllerDevice",
            )
            while True:
                try:
                    usb  = watcher()
                    data = {"device": str(usb)}
                    write_log("usb_connected", data, "usb")
                except Exception:
                    time.sleep(5)
        except Exception as e2:
            print(f"[USBMonitor] Could not start USB monitoring: {e2}")
