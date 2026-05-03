"""Minimal APK (Android package) containing the EICAR signature.

APK is a ZIP archive with a known manifest layout. We produce a structurally
valid (though unsigned and unrunnable) APK that contains:
  - AndroidManifest.xml (text form, sufficient for static parsers)
  - assets/eicar.txt with the EICAR signature
  - classes.dex stub bearing the EICAR signature

Static AV/EDR APK scanners will detect the signature in the assets and dex
entries.
"""
import io
import zipfile

from .eicar import EICAR_STRING

ANDROID_MANIFEST_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.bluetest.eicar"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="EICARTest">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def eicar_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", ANDROID_MANIFEST_XML)
        # EICAR-bearing entries are stored uncompressed so static byte
        # scanners detect the signature without first inflating the ZIP.
        z.writestr(
            zipfile.ZipInfo("assets/eicar.txt"),
            EICAR_STRING,
            compress_type=zipfile.ZIP_STORED,
        )
        dex = b"dex\n035\x00" + b"\x00" * 24 + EICAR_STRING
        z.writestr(
            zipfile.ZipInfo("classes.dex"),
            dex,
            compress_type=zipfile.ZIP_STORED,
        )
        z.writestr(
            zipfile.ZipInfo("resources.arsc"),
            b"\x02\x00\x0c\x00" + b"\x00" * 8 + EICAR_STRING,
            compress_type=zipfile.ZIP_STORED,
        )
        z.writestr(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\nCreated-By: csp\n\n",
        )
    return buf.getvalue()
