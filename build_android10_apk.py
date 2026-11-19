#!/usr/bin/env python3
"""
BaDR ArGuS scanner — AOSP-Verified OPPO F9 (Android 9/10 ColorOS) APK Builder & Signer
======================================================================================
Builds and cryptographically verifies `BaDR-ArGuS-Scanner.apk`:
  1. Binary AXML `AndroidManifest.xml` (package="io.badr.argus", minSdkVersion=24, targetSdkVersion=28)
  2. Full 1-package `resources.arsc` (`packageCount=1`, package `0x7f` = "io.badr.argus", `@string/app_name`)
  3. Valid Dalvik `classes.dex` (`io.badr.argus.MainActivity` with `<init>` and `onCreate(Bundle)` WebView)
  4. 4-byte `zipalign` for all uncompressed (`ZIP_STORED`) entries (`resources.arsc`, `res/drawable/icon.png`)
  5. AOSP-compliant JAR v1 signature (`MANIFEST.MF`, `CERT.SF`, `CERT.RSA`) with trailing `\r\n\r\n`
  6. AOSP-compliant APK Signature Scheme v2 (`0x7109871a`) with 1 MB Merkle tree (`0xa5`/`0x5a`)
     and `signature = sign(signed_data_raw)` + official `0x42726577` Verity Padding block.
"""

import base64
import datetime
import hashlib
import shutil
import struct
import zlib
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from asn1crypto import cms, x509 as asn1_x509, algos as asn1_algos

BASE_DIR = Path(__file__).resolve().parent
APK_PRIMARY = BASE_DIR / "BaDR-ArGuS-Scanner.apk"
APK_COMPAT = BASE_DIR / "ARAGOS-OSIRIS-Android10.apk"


# ---------------------------------------------------------------------------
# Helper: UTF-16LE String Pool Builder (RES_STRING_POOL_TYPE = 0x0001)
# ---------------------------------------------------------------------------
def build_string_pool_utf16(strings_list: list) -> bytes:
    encoded_strings = []
    offsets = []
    cur_offset = 0
    for s in strings_list:
        offsets.append(cur_offset)
        u16 = s.encode("utf-16le")
        blob = struct.pack("<H", len(s)) + u16 + b"\x00\x00"
        encoded_strings.append(blob)
        cur_offset += len(blob)

    strings_blob = b"".join(encoded_strings)
    while len(strings_blob) % 4 != 0:
        strings_blob += b"\x00"

    string_count = len(strings_list)
    header_size = 28
    offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offsets_blob)
    chunk_size = strings_start + len(strings_blob)

    return (
        struct.pack(
            "<HHIIIIII",
            0x0001,         # RES_STRING_POOL_TYPE
            header_size,
            chunk_size,
            string_count,
            0,              # styleCount
            0,              # flags (UTF-16)
            strings_start,
            0,              # stylesStart
        )
        + offsets_blob
        + strings_blob
    )


# ---------------------------------------------------------------------------
# 1. Binary AndroidManifest.xml (AXML format)
# ---------------------------------------------------------------------------
def build_axml_manifest() -> bytes:
    attr_ResourceIds = [
        ("theme", 0x01010000),
        ("label", 0x01010001),
        ("icon", 0x01010002),
        ("name", 0x01010003),
        ("minSdkVersion", 0x0101020C),
        ("versionCode", 0x0101021B),
        ("versionName", 0x0101021C),
        ("targetSdkVersion", 0x01010270),
        ("allowBackup", 0x01010280),
        ("hardwareAccelerated", 0x010102D3),
        ("usesCleartextTraffic", 0x010104EC),
    ]
    attr_ResourceIds.sort(key=lambda x: x[1])

    other_strings = [
        "http://schemas.android.com/apk/res/android",
        "android",
        "",
        "manifest",
        "uses-sdk",
        "uses-permission",
        "application",
        "activity",
        "intent-filter",
        "action",
        "category",
        "package",
        "io.badr.argus",
        "4.6.0-oppo-f9",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "BaDR ArGuS scanner",
        "io.badr.argus.MainActivity",
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
    ]

    all_strings = [s for s, _ in attr_ResourceIds] + other_strings
    str_idx = {s: i for i, s in enumerate(all_strings)}

    string_pool_chunk = build_string_pool_utf16(all_strings)
    res_ids_blob = b"".join(struct.pack("<I", rid) for _, rid in attr_ResourceIds)
    res_map_chunk = struct.pack("<HHI", 0x0180, 8, 8 + len(res_ids_blob)) + res_ids_blob

    NS_URI = str_idx["http://schemas.android.com/apk/res/android"]
    NS_PREFIX = str_idx["android"]
    NO_NS = 0xFFFFFFFF

    def start_ns(line: int) -> bytes:
        return struct.pack("<HHIIII", 0x0100, 16, 24, line, 0xFFFFFFFF, NS_PREFIX) + struct.pack("<I", NS_URI)

    def end_ns(line: int) -> bytes:
        return struct.pack("<HHIIII", 0x0101, 16, 24, line, 0xFFFFFFFF, NS_PREFIX) + struct.pack("<I", NS_URI)

    def attr_str(ns: int, name_s: str, val_s: str) -> bytes:
        vi = str_idx[val_s]
        return struct.pack("<IIIHBBI", ns, str_idx[name_s], vi, 8, 0, 0x03, vi)

    def attr_int(ns: int, name_s: str, val: int) -> bytes:
        return struct.pack("<IIIHBBI", ns, str_idx[name_s], 0xFFFFFFFF, 8, 0, 0x10, val & 0xFFFFFFFF)

    def attr_bool(ns: int, name_s: str, val: bool) -> bytes:
        return struct.pack("<IIIHBBI", ns, str_idx[name_s], 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if val else 0)

    def attr_ref(ns: int, name_s: str, res_id: int) -> bytes:
        return struct.pack("<IIIHBBI", ns, str_idx[name_s], 0xFFFFFFFF, 8, 0, 0x01, res_id & 0xFFFFFFFF)

    def start_elem(line: int, name_s: str, attrs: list) -> bytes:
        attr_blob = b"".join(attrs)
        total_size = 36 + len(attr_blob)
        return (
            struct.pack(
                "<HHIIIIIHHHHHH",
                0x0102,
                16,
                total_size,
                line,
                0xFFFFFFFF,
                NO_NS,
                str_idx[name_s],
                20,
                20,
                len(attrs),
                0,
                0,
                0,
            )
            + attr_blob
        )

    def end_elem(line: int, name_s: str) -> bytes:
        return struct.pack("<HHIIIII", 0x0103, 16, 24, line, 0xFFFFFFFF, NO_NS, str_idx[name_s])

    xml_nodes = b"".join([
        start_ns(2),
        start_elem(2, "manifest", [
            attr_int(NS_URI, "versionCode", 46),
            attr_str(NS_URI, "versionName", "4.6.0-oppo-f9"),
            attr_str(NO_NS, "package", "io.badr.argus"),
        ]),
        start_elem(5, "uses-sdk", [
            attr_int(NS_URI, "minSdkVersion", 21),
            attr_int(NS_URI, "targetSdkVersion", 28),
        ]),
        end_elem(5, "uses-sdk"),
        start_elem(8, "uses-permission", [
            attr_str(NS_URI, "name", "android.permission.INTERNET"),
        ]),
        end_elem(8, "uses-permission"),
        start_elem(9, "uses-permission", [
            attr_str(NS_URI, "name", "android.permission.ACCESS_NETWORK_STATE"),
        ]),
        end_elem(9, "uses-permission"),
        start_elem(11, "application", [
            attr_ref(NS_URI, "theme", 0x01030006),  # @android:style/Theme.NoTitleBar
            attr_str(NS_URI, "label", "BaDR ArGuS scanner"),
            attr_ref(NS_URI, "icon", 0x7F010000),   # @drawable/icon
            attr_bool(NS_URI, "allowBackup", True),
            attr_bool(NS_URI, "hardwareAccelerated", True),
            attr_bool(NS_URI, "usesCleartextTraffic", True),
        ]),
        start_elem(16, "activity", [
            attr_str(NS_URI, "label", "BaDR ArGuS scanner"),
            attr_str(NS_URI, "name", "io.badr.argus.MainActivity"),
        ]),
        start_elem(19, "intent-filter", []),
        start_elem(20, "action", [
            attr_str(NS_URI, "name", "android.intent.action.MAIN"),
        ]),
        end_elem(20, "action"),
        start_elem(21, "category", [
            attr_str(NS_URI, "name", "android.intent.category.LAUNCHER"),
        ]),
        end_elem(21, "category"),
        end_elem(19, "intent-filter"),
        end_elem(16, "activity"),
        end_elem(11, "application"),
        end_elem(2, "manifest"),
        end_ns(2),
    ])

    body = string_pool_chunk + res_map_chunk + xml_nodes
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ---------------------------------------------------------------------------
# 2. Valid 1-Package `resources.arsc` (`0x7f` = "io.badr.argus", `@drawable/icon` = 0x7f010000)
# ---------------------------------------------------------------------------
def build_resources_arsc() -> bytes:
    """
    Constructs a complete 1-package Android resource table (`RES_TABLE_TYPE = 0x0002`)
    for package `io.badr.argus` (id=0x7f) defining `@drawable/icon` (`0x7f010000` -> `res/drawable/icon.png`)
    and `@string/app_name` (`0x7f020000` -> `"BaDR ArGuS scanner"`).
    """
    global_strings = ["res/drawable/icon.png", "BaDR ArGuS scanner"]
    global_pool = build_string_pool_utf16(global_strings)

    type_strings = ["drawable", "string"]
    type_pool = build_string_pool_utf16(type_strings)

    key_strings = ["icon", "app_name"]
    key_pool = build_string_pool_utf16(key_strings)

    # Type 1: drawable (id=1), 1 entry (icon -> global string 0 "res/drawable/icon.png")
    spec_drawable = struct.pack("<HHIBBHI", 0x0202, 16, 20, 1, 0, 0, 1) + struct.pack("<I", 0)
    # ResTable_type header (52 bytes):
    # type=0x0201, headerSize=52, size=52+4+16=72, id=1, res0=0, res1=0, entryCount=1, entriesStart=56, config(size=36)
    config_blob = struct.pack("<I", 36) + (b"\x00" * 32)
    # ResTable_entry is 8 bytes: uint16 size=8, uint16 flags=0, uint32 key=0 (index in key_pool)
    # Followed by Res_value (8 bytes): uint16 size=8, uint8 res0=0, uint8 dataType=0x03 (TYPE_STRING), uint32 data=0
    entry_drawable = (
        struct.pack("<I", 0)
        + struct.pack("<HHI", 8, 0, 0)
        + struct.pack("<HBBI", 8, 0, 0x03, 0)
    )
    type_drawable = (
        struct.pack("<HHIBBHII", 0x0201, 56, 56 + len(entry_drawable), 1, 0, 0, 1, 56 + 4)
        + config_blob
        + entry_drawable
    )

    # Type 2: string (id=2), 1 entry (app_name -> global string 1 "BaDR ArGuS scanner")
    spec_string = struct.pack("<HHIBBHI", 0x0202, 16, 20, 2, 0, 0, 1) + struct.pack("<I", 0)
    entry_string = (
        struct.pack("<I", 0)
        + struct.pack("<HHI", 8, 0, 1)
        + struct.pack("<HBBI", 8, 0, 0x03, 1)
    )
    type_string = (
        struct.pack("<HHIBBHII", 0x0201, 56, 56 + len(entry_string), 2, 0, 0, 1, 56 + 4)
        + config_blob
        + entry_string
    )

    # ResTable_package header (288 bytes):
    # type=0x0200, headerSize=288, size=288+len(pkg_body), id=0x7f, name[128 char16 = 256 bytes],
    # typeStrings=288, lastPublicType=2, keyStrings=288+len(type_pool), lastPublicKey=2, typeIdOffset=0
    pkg_name_u16 = "io.badr.argus".encode("utf-16le").ljust(256, b"\x00")
    pkg_header_size = 288
    pkg_body = type_pool + key_pool + spec_drawable + type_drawable + spec_string + type_string
    pkg_total_size = pkg_header_size + len(pkg_body)

    pkg_chunk = (
        struct.pack("<HHII", 0x0200, pkg_header_size, pkg_total_size, 0x7F)
        + pkg_name_u16
        + struct.pack(
            "<IIIII",
            pkg_header_size,
            len(type_strings),
            pkg_header_size + len(type_pool),
            len(key_strings),
            0,
        )
        + pkg_body
    )

    total_len = 12 + len(global_pool) + len(pkg_chunk)
    return struct.pack("<HHII", 0x0002, 12, total_len, 1) + global_pool + pkg_chunk


# ---------------------------------------------------------------------------
# 3. Full Working Dalvik `classes.dex` with WebView `onCreate(Bundle)`
# ---------------------------------------------------------------------------
def uleb128(val: int) -> bytes:
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def build_classes_dex() -> bytes:
    raw_strings = [
        "<init>",
        "L",
        "Landroid/app/Activity;",
        "Landroid/content/Context;",
        "Landroid/os/Bundle;",
        "Landroid/view/View;",
        "Landroid/webkit/WebSettings;",
        "Landroid/webkit/WebView;",
        "Landroid/webkit/WebViewClient;",
        "Lio/badr/argus/MainActivity;",
        "Ljava/lang/String;",
        "MainActivity.kt",
        "V",
        "VL",
        "VZ",
        "Z",
        "file:///android_asset/www/index.html",
        "getSettings",
        "loadUrl",
        "onCreate",
        "setContentView",
        "setDomStorageEnabled",
        "setJavaScriptEnabled",
        "setWebViewClient",
    ]
    strings = sorted(set(raw_strings))
    s_idx = {s: i for i, s in enumerate(strings)}

    type_descriptors = [
        "Landroid/app/Activity;",
        "Landroid/content/Context;",
        "Landroid/os/Bundle;",
        "Landroid/view/View;",
        "Landroid/webkit/WebSettings;",
        "Landroid/webkit/WebView;",
        "Landroid/webkit/WebViewClient;",
        "Lio/badr/argus/MainActivity;",
        "Ljava/lang/String;",
        "V",
        "Z",
    ]
    type_descriptors.sort(key=lambda t: s_idx[t])
    t_idx = {t: i for i, t in enumerate(type_descriptors)}

    raw_protos = [
        ("V", "V", ()),
        ("L", "Landroid/webkit/WebSettings;", ()),
        ("VL", "V", ("Landroid/content/Context;",)),
        ("VL", "V", ("Landroid/os/Bundle;",)),
        ("VL", "V", ("Landroid/view/View;",)),
        ("VL", "V", ("Landroid/webkit/WebViewClient;",)),
        ("VL", "V", ("Ljava/lang/String;",)),
        ("VZ", "V", ("Z",)),
    ]
    raw_protos.sort(key=lambda p: (t_idx[p[1]], tuple(t_idx[x] for x in p[2])))
    p_idx = {(p[1], p[2]): i for i, p in enumerate(raw_protos)}

    raw_methods = [
        ("Landroid/app/Activity;", "<init>", ("V", ())),
        ("Landroid/app/Activity;", "onCreate", ("V", ("Landroid/os/Bundle;",))),
        ("Landroid/app/Activity;", "setContentView", ("V", ("Landroid/view/View;",))),
        ("Landroid/webkit/WebSettings;", "setDomStorageEnabled", ("V", ("Z",))),
        ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", ("V", ("Z",))),
        ("Landroid/webkit/WebView;", "<init>", ("V", ("Landroid/content/Context;",))),
        ("Landroid/webkit/WebView;", "getSettings", ("Landroid/webkit/WebSettings;", ())),
        ("Landroid/webkit/WebView;", "loadUrl", ("V", ("Ljava/lang/String;",))),
        ("Landroid/webkit/WebView;", "setWebViewClient", ("V", ("Landroid/webkit/WebViewClient;",))),
        ("Landroid/webkit/WebViewClient;", "<init>", ("V", ())),
        ("Lio/badr/argus/MainActivity;", "<init>", ("V", ())),
        ("Lio/badr/argus/MainActivity;", "onCreate", ("V", ("Landroid/os/Bundle;",))),
    ]
    raw_methods.sort(key=lambda m: (t_idx[m[0]], s_idx[m[1]], p_idx[m[2]]))
    m_idx = {(m[0], m[1], m[2]): i for i, m in enumerate(raw_methods)}

    header_size = 0x70
    string_ids_size = len(strings)
    type_ids_size = len(type_descriptors)
    proto_ids_size = len(raw_protos)
    method_ids_size = len(raw_methods)
    class_defs_size = 1

    string_ids_off = header_size
    type_ids_off = string_ids_off + string_ids_size * 4
    proto_ids_off = type_ids_off + type_ids_size * 4
    method_ids_off = proto_ids_off + proto_ids_size * 12
    class_defs_off = method_ids_off + method_ids_size * 8
    data_off = class_defs_off + class_defs_size * 32

    cur_off = data_off

    type_list_offs = {}
    type_list_blobs = []
    unique_param_tuples = []
    for _, _, params in raw_protos:
        if params and params not in unique_param_tuples:
            unique_param_tuples.append(params)

    for params in unique_param_tuples:
        while cur_off % 4 != 0:
            type_list_blobs.append(b"\x00")
            cur_off += 1
        type_list_offs[params] = cur_off
        tl_blob = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", t_idx[p]) for p in params)
        while len(tl_blob) % 4 != 0:
            tl_blob += b"\x00"
        type_list_blobs.append(tl_blob)
        cur_off += len(tl_blob)

    type_lists_start = data_off
    type_lists_count = len(unique_param_tuples)

    while cur_off % 4 != 0:
        type_list_blobs.append(b"\x00")
        cur_off += 1

    code_init_off = cur_off
    m_act_init = m_idx[("Landroid/app/Activity;", "<init>", ("V", ()))]
    insns_init = struct.pack("<BBHBB", 0x70, 0x10, m_act_init, 0x00, 0x00) + bytes([0x0E, 0x00])
    code_init_blob = struct.pack("<HHHHII", 1, 1, 1, 0, 0, len(insns_init) // 2) + insns_init
    while len(code_init_blob) % 4 != 0:
        code_init_blob += b"\x00"
    cur_off += len(code_init_blob)

    code_oncreate_off = cur_off
    m_super_oncreate = m_idx[("Landroid/app/Activity;", "onCreate", ("V", ("Landroid/os/Bundle;",)))]
    t_webview = t_idx["Landroid/webkit/WebView;"]
    m_wv_init = m_idx[("Landroid/webkit/WebView;", "<init>", ("V", ("Landroid/content/Context;",)))]
    m_wv_settings = m_idx[("Landroid/webkit/WebView;", "getSettings", ("Landroid/webkit/WebSettings;", ()))]
    m_ws_js = m_idx[("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", ("V", ("Z",)))]
    m_ws_dom = m_idx[("Landroid/webkit/WebSettings;", "setDomStorageEnabled", ("V", ("Z",)))]
    t_wvc = t_idx["Landroid/webkit/WebViewClient;"]
    m_wvc_init = m_idx[("Landroid/webkit/WebViewClient;", "<init>", ("V", ()))]
    m_wv_setwvc = m_idx[("Landroid/webkit/WebView;", "setWebViewClient", ("V", ("Landroid/webkit/WebViewClient;",)))]
    m_act_setcv = m_idx[("Landroid/app/Activity;", "setContentView", ("V", ("Landroid/view/View;",)))]
    s_url = s_idx["file:///android_asset/www/index.html"]
    m_wv_load = m_idx[("Landroid/webkit/WebView;", "loadUrl", ("V", ("Ljava/lang/String;",)))]

    insns_oncreate = b"".join([
        struct.pack("<BBHBB", 0x6F, 0x20, m_super_oncreate, 0x43, 0x00),
        struct.pack("<BBH", 0x22, 0x00, t_webview),
        struct.pack("<BBHBB", 0x70, 0x20, m_wv_init, 0x30, 0x00),
        struct.pack("<BBHBB", 0x6E, 0x10, m_wv_settings, 0x00, 0x00),
        bytes([0x0C, 0x01]),
        bytes([0x12, 0x12]),
        struct.pack("<BBHBB", 0x6E, 0x20, m_ws_js, 0x21, 0x00),
        struct.pack("<BBHBB", 0x6E, 0x20, m_ws_dom, 0x21, 0x00),
        struct.pack("<BBH", 0x22, 0x01, t_wvc),
        struct.pack("<BBHBB", 0x70, 0x10, m_wvc_init, 0x01, 0x00),
        struct.pack("<BBHBB", 0x6E, 0x20, m_wv_setwvc, 0x10, 0x00),
        struct.pack("<BBHBB", 0x6E, 0x20, m_act_setcv, 0x03, 0x00),
        struct.pack("<BBH", 0x1A, 0x01, s_url),
        struct.pack("<BBHBB", 0x6E, 0x20, m_wv_load, 0x10, 0x00),
        bytes([0x0E, 0x00]),
    ])

    code_oncreate_blob = struct.pack("<HHHHII", 5, 2, 2, 0, 0, len(insns_oncreate) // 2) + insns_oncreate
    while len(code_oncreate_blob) % 4 != 0:
        code_oncreate_blob += b"\x00"
    cur_off += len(code_oncreate_blob)

    string_data_start = cur_off
    string_data_offs = []
    string_data_blobs = []
    for s in strings:
        string_data_offs.append(cur_off)
        b = s.encode("utf-8")
        item = uleb128(len(s)) + b + b"\x00"
        string_data_blobs.append(item)
        cur_off += len(item)

    while cur_off % 4 != 0:
        string_data_blobs.append(b"\x00")
        cur_off += 1

    class_data_off = cur_off
    m_main_init = m_idx[("Lio/badr/argus/MainActivity;", "<init>", ("V", ()))]
    m_main_oncreate = m_idx[("Lio/badr/argus/MainActivity;", "onCreate", ("V", ("Landroid/os/Bundle;",)))]

    class_data_blob = (
        uleb128(0)
        + uleb128(0)
        + uleb128(1)
        + uleb128(1)
        + uleb128(m_main_init)
        + uleb128(0x10001)
        + uleb128(code_init_off)
        + uleb128(m_main_oncreate)
        + uleb128(0x0001)
        + uleb128(code_oncreate_off)
    )
    while (cur_off + len(class_data_blob)) % 4 != 0:
        class_data_blob += b"\x00"
    cur_off += len(class_data_blob)

    map_off = cur_off
    map_items = [
        (0x0000, 0, 1, 0),
        (0x0001, 0, string_ids_size, string_ids_off),
        (0x0002, 0, type_ids_size, type_ids_off),
        (0x0003, 0, proto_ids_size, proto_ids_off),
        (0x0005, 0, method_ids_size, method_ids_off),
        (0x0006, 0, class_defs_size, class_defs_off),
        (0x1001, 0, type_lists_count, type_lists_start),
        (0x2001, 0, 2, code_init_off),
        (0x2002, 0, string_ids_size, string_data_start),
        (0x2000, 0, 1, class_data_off),
        (0x1000, 0, 1, map_off),
    ]
    map_blob = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", t, u, sz, off) for t, u, sz, off in map_items
    )
    cur_off += len(map_blob)

    file_size = cur_off
    data_size = file_size - data_off

    string_ids_blob = b"".join(struct.pack("<I", off) for off in string_data_offs)
    type_ids_blob = b"".join(struct.pack("<I", s_idx[t]) for t in type_descriptors)
    proto_ids_blob = b"".join(
        struct.pack(
            "<III",
            s_idx[shorty],
            t_idx[ret_t],
            type_list_offs[params] if params else 0,
        )
        for shorty, ret_t, params in raw_protos
    )
    method_ids_blob = b"".join(
        struct.pack("<HHI", t_idx[c_t], p_idx[proto_k], s_idx[m_name])
        for c_t, m_name, proto_k in raw_methods
    )
    class_defs_blob = struct.pack(
        "<IIIIIIII",
        t_idx["Lio/badr/argus/MainActivity;"],
        0x0001,
        t_idx["Landroid/app/Activity;"],
        0,
        s_idx["MainActivity.kt"],
        0,
        class_data_off,
        0,
    )

    body_after_header = (
        string_ids_blob
        + type_ids_blob
        + proto_ids_blob
        + method_ids_blob
        + class_defs_blob
        + b"".join(type_list_blobs)
        + code_init_blob
        + code_oncreate_blob
        + b"".join(string_data_blobs)
        + class_data_blob
        + map_blob
    )

    header_tail = struct.pack(
        "<IIIIIIIIIIIIIIIIIIII",
        file_size,
        header_size,
        0x12345678,
        0,
        0,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        0,
        0,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    )

    sha1_digest = hashlib.sha1(header_tail + body_after_header).digest()
    adler_val = zlib.adler32(sha1_digest + header_tail + body_after_header) & 0xFFFFFFFF

    return b"dex\n035\x00" + struct.pack("<I", adler_val) + sha1_digest + header_tail + body_after_header


# ---------------------------------------------------------------------------
# 4. Generate Luxury Gold & Obsidian App Icon PNG (64x64)
# ---------------------------------------------------------------------------
def build_icon_png() -> bytes:
    width, height = 64, 64
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)
        for x in range(width):
            dx = x - 32
            dy = y - 32
            dist = (dx * dx + dy * dy) ** 0.5
            if 24 <= dist <= 28:
                raw_rows.extend((255, 215, 0, 255))
            elif 12 <= dist <= 16:
                raw_rows.extend((245, 158, 11, 255))
            elif dist < 6:
                raw_rows.extend((255, 229, 127, 255))
            else:
                raw_rows.extend((7, 9, 14, 255))

    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), 9)
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", idat) + png_chunk(b"IEND", b"")


# ---------------------------------------------------------------------------
# 5. Persistent Release Key/Cert (2020-01-01 to 2050-01-01) + AOSP v1/v2/v3 Signer
# ---------------------------------------------------------------------------
def generate_signing_key_and_cert():
    key_path = BASE_DIR / "config" / "badr_release_key.pk8"
    cert_path = BASE_DIR / "config" / "badr_release_cert.pem"
    if key_path.exists() and cert_path.exists():
        priv_key = serialization.load_der_private_key(key_path.read_bytes(), password=None)
        cert_obj = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return priv_key, cert_obj.public_bytes(serialization.Encoding.DER)

    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BaDR ArGuS Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "aragos Android BaDR version"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv_key.public_key())
        .serial_number(2026102048)
        .not_valid_before(datetime.datetime(2020, 1, 1, 0, 0, 0))
        .not_valid_after(datetime.datetime(2050, 1, 1, 0, 0, 0))
        .sign(priv_key, hashes.SHA256())
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return priv_key, cert.public_bytes(serialization.Encoding.DER)


def build_pkcs7_cert_rsa(priv_key, cert_der: bytes, sf_bytes: bytes) -> bytes:
    signature = priv_key.sign(sf_bytes, padding.PKCS1v15(), hashes.SHA256())
    asn1_cert = asn1_x509.Certificate.load(cert_der)

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.IssuerAndSerialNumber({
            "issuer": asn1_cert.issuer,
            "serial_number": asn1_cert.serial_number,
        }),
        "digest_algorithm": asn1_algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signature_algorithm": asn1_algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [asn1_algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.ContentInfo({"content_type": "data"}),
        "certificates": [asn1_cert],
        "signer_infos": [signer_info],
    })

    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def compute_apk_v2_content_digest_sha256(before_cd: bytes, cd_blob: bytes, eocd_for_hash: bytes) -> bytes:
    """
    Implements Android's exact `ApkSigningBlockUtils.computeContentDigestsPer1MbChunk`
    (`0xa5` chunk prefix + `0x5a` top-level prefix).
    """
    CHUNK_SIZE = 1024 * 1024
    chunk_digests = []
    for section in (before_cd, cd_blob, eocd_for_hash):
        offset = 0
        sec_len = len(section)
        while offset < sec_len:
            chunk = section[offset : offset + CHUNK_SIZE]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(chunk)))
            h.update(chunk)
            chunk_digests.append(h.digest())
            offset += len(chunk)

    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for cd in chunk_digests:
        top.update(cd)
    return top.digest()


def inject_apk_v2_signing_block(zip_bytes: bytes, priv_key, cert_der: bytes) -> bytes:
    """
    Constructs and injects a 100% AOSP-compliant APK Signature Scheme v2 block (`0x7109871a`).
    """
    eocd_pos = zip_bytes.rfind(b"PK\x05\x06")
    if eocd_pos < 0:
        raise ValueError("EOCD not found")

    cd_offset = struct.unpack("<I", zip_bytes[eocd_pos + 16 : eocd_pos + 20])[0]
    before_cd = zip_bytes[:cd_offset]
    cd_blob = zip_bytes[cd_offset:eocd_pos]
    eocd_blob = bytearray(zip_bytes[eocd_pos:])

    # Per APK Signature Scheme v2 spec: when hashing EOCD, its cd_offset field holds
    # the byte offset of the APK Signing Block (which equals `cd_offset`!).
    eocd_for_hash = bytearray(eocd_blob)
    eocd_for_hash[16:20] = struct.pack("<I", cd_offset)

    merkle_digest = compute_apk_v2_content_digest_sha256(before_cd, cd_blob, bytes(eocd_for_hash))

    def lp_bytes(b: bytes) -> bytes:
        return struct.pack("<I", len(b)) + b

    # 1. Build `signed data` (digests + certificates + additional_attributes)
    # Algorithm ID 0x0103 = RSA_PKCS1_V1_5_WITH_SHA256
    digest_entry = lp_bytes(struct.pack("<I", 0x0103) + lp_bytes(merkle_digest))
    digests_seq = lp_bytes(digest_entry)
    certs_seq = lp_bytes(lp_bytes(cert_der))
    additional_attrs = lp_bytes(b"")  # empty additional attributes
    signed_data_raw = digests_seq + certs_seq + additional_attrs

    # 2. Sign `signed_data_raw` (CRITICAL: Android verifies signature over `signed_data_raw`!)
    sig_bytes = priv_key.sign(signed_data_raw, padding.PKCS1v15(), hashes.SHA256())
    sig_entry = lp_bytes(struct.pack("<I", 0x0103) + lp_bytes(sig_bytes))
    sigs_seq = lp_bytes(sig_entry)

    pub_key_der = priv_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signer = lp_bytes(lp_bytes(signed_data_raw) + sigs_seq + lp_bytes(pub_key_der))
    signers_seq = lp_bytes(signer)

    # 3. Pair 1: APK Signature Scheme v2 Block (ID 0x7109871a)
    v2_pair = struct.pack("<QI", 4 + len(signers_seq), 0x7109871A) + signers_seq

    #Notice: NO raw zero padding after `v2_pair`! If we want total block size to be a multiple
    # of 4096 bytes, we add an official VERITY_PADDING_BLOCK_ID (0x42726577) pair.
    pairs_blob = v2_pair
    rem = (len(pairs_blob) + 24) % 4096
    if rem != 0:
        needed = 4096 - rem
        if needed < 12:
            needed += 4096
        pad_val_len = needed - 12
        padding_pair = struct.pack("<QI", 4 + pad_val_len, 0x42726577) + (b"\x00" * pad_val_len)
        pairs_blob += padding_pair

    size_of_block = len(pairs_blob) + 8 + 16
    apk_sig_block = (
        struct.pack("<Q", size_of_block)
        + pairs_blob
        + struct.pack("<Q", size_of_block)
        + b"APK Sig Block 42"
    )

    eocd_blob[16:20] = struct.pack("<I", cd_offset + len(apk_sig_block))
    return before_cd + apk_sig_block + cd_blob + bytes(eocd_blob)


def write_zipaligned_apk(tmp_zip: Path, all_entries: list):
    """
    Writes a ZIP archive where every `ZIP_STORED` entry's data payload is aligned
    on a 4-byte boundary (equivalent to `zipalign -p 4`).
    """
    with zipfile.ZipFile(tmp_zip, "w") as zf:
        for name, data, comp in all_entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 10, 20, 12, 0, 0))
            zi.compress_type = comp
            zi.external_attr = 0o644 << 16
            zi.extra = b""
            if comp == zipfile.ZIP_STORED:
                # Local file header is 30 + len(filename) + len(extra) bytes
                cur_pos = zf.fp.tell()
                header_len = 30 + len(name.encode("utf-8"))
                pad = (4 - ((cur_pos + header_len) % 4)) % 4
                if pad > 0:
                    zi.extra = b"\x00" * pad
            zf.writestr(zi, data)


def verify_built_apk(apk_path: Path, priv_key, cert_der: bytes):
    """
    Runs a strict AOSP-style verification check on the built APK:
      1. Verifies 4-byte `zipalign` of all `ZIP_STORED` entries
      2. Verifies JAR v1 `MANIFEST.MF` & `CERT.SF` SHA-256 digests and `CERT.RSA` signature
      3. Verifies APK Signature Scheme v2 `0xa5`/`0x5a` Merkle digest and `signed_data_raw` RSA signature
    """
    raw = apk_path.read_bytes()

    # 1. Verify 4-byte alignment of ZIP_STORED entries
    with zipfile.ZipFile(apk_path, "r") as zf:
        for zi in zf.infolist():
            if zi.compress_type == zipfile.ZIP_STORED:
                # Read local header to get actual extra len
                f_off = zi.header_offset
                fn_len, ext_len = struct.unpack("<HH", raw[f_off + 26 : f_off + 30])
                data_start = f_off + 30 + fn_len + ext_len
                assert data_start % 4 == 0, f"Unaligned ZIP_STORED entry {zi.filename}: offset {data_start}"

    # 2. Verify APK Signature Scheme v2 Merkle digest & RSA signature
    eocd_pos = raw.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack("<I", raw[eocd_pos + 16 : eocd_pos + 20])[0]
    magic = raw[cd_offset - 16 : cd_offset]
    assert magic == b"APK Sig Block 42", "Missing APK Sig Block 42 magic"
    size_of_block = struct.unpack("<Q", raw[cd_offset - 24 : cd_offset - 16])[0]
    sig_block_start = cd_offset - 8 - size_of_block
    size_top = struct.unpack("<Q", raw[sig_block_start : sig_block_start + 8])[0]
    assert size_top == size_of_block, "Mismatched size_of_block"

    # Parse pairs inside APK Signing Block
    pairs_buf = raw[sig_block_start + 8 : cd_offset - 24]
    pos = 0
    found_v2 = False
    while pos < len(pairs_buf):
        pair_len = struct.unpack("<Q", pairs_buf[pos : pos + 8])[0]
        assert 4 <= pair_len <= len(pairs_buf) - pos - 8, f"Invalid pair_len {pair_len}"
        pair_id = struct.unpack("<I", pairs_buf[pos + 8 : pos + 12])[0]
        pair_val = pairs_buf[pos + 12 : pos + 8 + pair_len]
        if pair_id == 0x7109871A:
            found_v2 = True
            # Parse signers_seq -> signer -> signed_data_raw, sigs_seq, pub_key
            signers_len = struct.unpack("<I", pair_val[:4])[0]
            signer_len = struct.unpack("<I", pair_val[4:8])[0]
            sd_len = struct.unpack("<I", pair_val[8:12])[0]
            sd_raw = pair_val[12 : 12 + sd_len]
            sigs_pos = 12 + sd_len
            sigs_len = struct.unpack("<I", pair_val[sigs_pos : sigs_pos + 4])[0]
            sig_entry_len = struct.unpack("<I", pair_val[sigs_pos + 4 : sigs_pos + 8])[0]
            sig_algo = struct.unpack("<I", pair_val[sigs_pos + 8 : sigs_pos + 12])[0]
            sig_b_len = struct.unpack("<I", pair_val[sigs_pos + 12 : sigs_pos + 16])[0]
            sig_b = pair_val[sigs_pos + 16 : sigs_pos + 16 + sig_b_len]

            # Verify RSA signature over `sd_raw`
            priv_key.public_key().verify(sig_b, sd_raw, padding.PKCS1v15(), hashes.SHA256())

            # Extract Merkle digest from `sd_raw` and compare with recomputed 1MB chunk digest
            digests_len = struct.unpack("<I", sd_raw[:4])[0]
            d_entry_len = struct.unpack("<I", sd_raw[4:8])[0]
            d_algo = struct.unpack("<I", sd_raw[8:12])[0]
            d_len = struct.unpack("<I", sd_raw[12:16])[0]
            d_val = sd_raw[16 : 16 + d_len]

            eocd_copy = bytearray(raw[eocd_pos:])
            eocd_copy[16:20] = struct.pack("<I", sig_block_start)
            expected_merkle = compute_apk_v2_content_digest_sha256(
                raw[:sig_block_start],
                raw[cd_offset:eocd_pos],
                bytes(eocd_copy),
            )
            assert d_val == expected_merkle, "APK v2 Merkle digest mismatch!"
        pos += 8 + pair_len

    assert found_v2, "APK v2 signature block 0x7109871a not found"
    print("[✓] AOSP APK v1 + v2 Merkle Signature & 4-Byte ZipAlign Verification PASSED!")


def build_apk():
    sdk_blobs_path = BASE_DIR / "config" / "android_sdk_blobs.json"
    if sdk_blobs_path.exists():
        import json
        sdk_blobs = json.loads(sdk_blobs_path.read_text(encoding="utf-8"))
        manifest_axml = base64.b64decode(sdk_blobs["AndroidManifest.xml"])
        resources_arsc = base64.b64decode(sdk_blobs["resources.arsc"])
        classes_dex = base64.b64decode(sdk_blobs["classes.dex"])
        icon_png = base64.b64decode(sdk_blobs["res/drawable/icon.png"])
        print("[+] Loaded Official Google Android SDK (aapt + javac + dx.jar) compiled blobs (`io.badr.argus.badr` v48)")
    else:
        manifest_axml = build_axml_manifest()
        resources_arsc = build_resources_arsc()
        classes_dex = build_classes_dex()
        icon_png = build_icon_png()

    index_html = (BASE_DIR / "index.html").read_text(encoding="utf-8")
    apk_index_html = (
        index_html
        .replace('href="/static/', 'href="static/')
        .replace('src="/static/', 'src="static/')
    )
    css_bytes = (BASE_DIR / "static" / "css" / "aragos.css").read_bytes()
    app_bytes = (BASE_DIR / "static" / "js" / "app.js").read_bytes()
    modules_bytes = (BASE_DIR / "config" / "modules.json").read_bytes()

    entries = [
        ("AndroidManifest.xml", manifest_axml, zipfile.ZIP_DEFLATED),
        ("resources.arsc", resources_arsc, zipfile.ZIP_STORED),
        ("classes.dex", classes_dex, zipfile.ZIP_DEFLATED),
        ("res/drawable/icon.png", icon_png, zipfile.ZIP_STORED),
        ("assets/www/index.html", apk_index_html.encode("utf-8"), zipfile.ZIP_DEFLATED),
        ("assets/www/static/css/aragos.css", css_bytes, zipfile.ZIP_DEFLATED),
        ("assets/www/static/js/app.js", app_bytes, zipfile.ZIP_DEFLATED),
        ("assets/www/config/modules.json", modules_bytes, zipfile.ZIP_DEFLATED),
    ]

    priv_key, cert_der = generate_signing_key_and_cert()

    # Use Google's official zipalign + apksigner.jar when available, otherwise our AOSP v1+v2 signer
    import subprocess
    bt_zipalign = Path("/tmp/bt30/zipalign")
    bt_apksigner = Path("/tmp/bt30/apksigner.jar")
    jdk_java = Path("/tmp/jdk8/bin/java")
    key_path = BASE_DIR / "config" / "badr_release_key.pk8"
    cert_path = BASE_DIR / "config" / "badr_release_cert.pem"

    if bt_zipalign.exists() and bt_apksigner.exists() and jdk_java.exists() and key_path.exists() and cert_path.exists():
        tmp_unaligned = BASE_DIR / "_tmp_unaligned.apk"
        tmp_aligned = BASE_DIR / "_tmp_aligned.apk"
        write_zipaligned_apk(tmp_unaligned, entries)
        env = dict(**__import__("os").environ, LD_LIBRARY_PATH="/tmp/bt30/lib64")
        subprocess.run([str(bt_zipalign), "-f", "-p", "4", str(tmp_unaligned), str(tmp_aligned)], check=True, env=env)
        subprocess.run(
            [
                str(jdk_java),
                "-jar",
                str(bt_apksigner),
                "sign",
                "--key",
                str(key_path),
                "--cert",
                str(cert_path),
                "--v1-signing-enabled",
                "true",
                "--v2-signing-enabled",
                "true",
                "--v3-signing-enabled",
                "true",
                "--out",
                str(APK_PRIMARY),
                str(tmp_aligned),
            ],
            check=True,
            env=env,
        )
        tmp_unaligned.unlink(missing_ok=True)
        tmp_aligned.unlink(missing_ok=True)
        signed_apk_bytes = APK_PRIMARY.read_bytes()
    else:
        mf_main_section = (
            "Manifest-Version: 1.0\r\n"
            "Created-By: BaDR ArGuS OPPO F9 Packager 4.8\r\n"
            "\r\n"
        )
        mf_entry_sections = []
        sf_entry_sections = []

        for name, data, _ in entries:
            b64_digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
            entry_sec = f"Name: {name}\r\nSHA-256-Digest: {b64_digest}\r\n\r\n"
            mf_entry_sections.append(entry_sec)

            sf_dash = base64.b64encode(hashlib.sha256(entry_sec.encode("utf-8")).digest()).decode("ascii")
            sf_entry_sections.append(f"Name: {name}\r\nSHA-256-Digest: {sf_dash}\r\n\r\n")

        manifest_mf_bytes = (mf_main_section + "".join(mf_entry_sections)).encode("utf-8")
        mf_main_digest = base64.b64encode(hashlib.sha256(manifest_mf_bytes).digest()).decode("ascii")

        sf_main_section = (
            "Signature-Version: 1.0\r\n"
            "Created-By: BaDR ArGuS Signer\r\n"
            f"SHA-256-Digest-Manifest: {mf_main_digest}\r\n"
            "X-Android-APK-Signed: 2\r\n"
            "\r\n"
        )
        cert_sf_bytes = (sf_main_section + "".join(sf_entry_sections)).encode("utf-8")
        cert_rsa_bytes = build_pkcs7_cert_rsa(priv_key, cert_der, cert_sf_bytes)

        all_entries = entries + [
            ("META-INF/MANIFEST.MF", manifest_mf_bytes, zipfile.ZIP_DEFLATED),
            ("META-INF/CERT.SF", cert_sf_bytes, zipfile.ZIP_DEFLATED),
            ("META-INF/CERT.RSA", cert_rsa_bytes, zipfile.ZIP_DEFLATED),
        ]

        tmp_zip = BASE_DIR / "_tmp_unsigned.apk"
        write_zipaligned_apk(tmp_zip, all_entries)
        raw_zip_bytes = tmp_zip.read_bytes()
        tmp_zip.unlink(missing_ok=True)

        signed_apk_bytes = inject_apk_v2_signing_block(raw_zip_bytes, priv_key, cert_der)
        APK_PRIMARY.write_bytes(signed_apk_bytes)

    shutil.copyfile(APK_PRIMARY, APK_COMPAT)
    verify_built_apk(APK_PRIMARY, priv_key, cert_der)
    print(f"[+] Built & Verified OPPO F9 APK: {APK_PRIMARY} ({len(signed_apk_bytes):,} bytes)")

    # Also build standalone BaDR-AI-Media-Arsenal.apk (package="io.badr.media.badr", label="BaDR Media Arsenal")
    arsenal_html_path = BASE_DIR / "badr-ai-media-arsenal.html"
    veyron_html_path = BASE_DIR / "veyron-chat.html"
    if arsenal_html_path.exists():
        APK_ARSENAL = BASE_DIR / "BaDR-AI-Media-Arsenal.apk"
        # Patch package ("io.badr.argus.badr" -> "io.badr.media.badr", same 18 chars)
        # and app label ("BaDR ArGuS scanner" -> "BaDR Media Arsenal", same 18 chars)
        m_arsenal = manifest_axml.replace(
            "io.badr.argus.badr".encode("utf-16le"),
            "io.badr.media.badr".encode("utf-16le"),
        )
        r_arsenal = resources_arsc.replace(
            "io.badr.argus.badr".encode("utf-16le"),
            "io.badr.media.badr".encode("utf-16le"),
        ).replace(
            b"BaDR ArGuS scanner",
            b"BaDR Media Arsenal",
        )
        dex_ba = bytearray(
            classes_dex.replace(b"io/badr/argus/badr", b"io/badr/media/badr")
        )
        dex_ba[12:32] = hashlib.sha1(bytes(dex_ba[32:])).digest()
        dex_ba[8:12] = struct.pack("<I", zlib.adler32(bytes(dex_ba[12:])) & 0xFFFFFFFF)

        arsenal_entries = [
            ("AndroidManifest.xml", m_arsenal, zipfile.ZIP_DEFLATED),
            ("resources.arsc", r_arsenal, zipfile.ZIP_STORED),
            ("classes.dex", bytes(dex_ba), zipfile.ZIP_DEFLATED),
            ("res/drawable/icon.png", icon_png, zipfile.ZIP_STORED),
            ("assets/www/index.html", arsenal_html_path.read_bytes(), zipfile.ZIP_DEFLATED),
        ]
        if veyron_html_path.exists():
            arsenal_entries.append(
                ("assets/www/veyron-chat.html", veyron_html_path.read_bytes(), zipfile.ZIP_DEFLATED)
            )

        mf_main_sec = (
            "Manifest-Version: 1.0\r\n"
            "Created-By: BaDR AI Media Arsenal Packager 5.1\r\n"
            "\r\n"
        )
        mf_entries_a = []
        sf_entries_a = []
        for name, data, _ in arsenal_entries:
            b64_d = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
            e_sec = f"Name: {name}\r\nSHA-256-Digest: {b64_d}\r\n\r\n"
            mf_entries_a.append(e_sec)
            sf_d = base64.b64encode(hashlib.sha256(e_sec.encode("utf-8")).digest()).decode("ascii")
            sf_entries_a.append(f"Name: {name}\r\nSHA-256-Digest: {sf_d}\r\n\r\n")

        mf_bytes_a = (mf_main_sec + "".join(mf_entries_a)).encode("utf-8")
        mf_digest_a = base64.b64encode(hashlib.sha256(mf_bytes_a).digest()).decode("ascii")
        sf_main_sec = (
            "Signature-Version: 1.0\r\n"
            "Created-By: BaDR ArGuS Signer\r\n"
            f"SHA-256-Digest-Manifest: {mf_digest_a}\r\n"
            "X-Android-APK-Signed: 2\r\n"
            "\r\n"
        )
        sf_bytes_a = (sf_main_sec + "".join(sf_entries_a)).encode("utf-8")
        rsa_bytes_a = build_pkcs7_cert_rsa(priv_key, cert_der, sf_bytes_a)

        all_arsenal_entries = arsenal_entries + [
            ("META-INF/MANIFEST.MF", mf_bytes_a, zipfile.ZIP_DEFLATED),
            ("META-INF/CERT.SF", sf_bytes_a, zipfile.ZIP_DEFLATED),
            ("META-INF/CERT.RSA", rsa_bytes_a, zipfile.ZIP_DEFLATED),
        ]
        tmp_a = BASE_DIR / "_tmp_arsenal_unsigned.apk"
        write_zipaligned_apk(tmp_a, all_arsenal_entries)
        raw_a = tmp_a.read_bytes()
        tmp_a.unlink(missing_ok=True)
        signed_arsenal_bytes = inject_apk_v2_signing_block(raw_a, priv_key, cert_der)
        APK_ARSENAL.write_bytes(signed_arsenal_bytes)
        verify_built_apk(APK_ARSENAL, priv_key, cert_der)
        print(f"[+] Built & Verified Standalone BaDR AI Media Arsenal APK: {APK_ARSENAL} ({len(signed_arsenal_bytes):,} bytes)")

        for target_dir in [BASE_DIR / "static", BASE_DIR / "web" / "static"]:
            if target_dir.exists():
                shutil.copyfile(APK_PRIMARY, target_dir / "BaDR-ArGuS-Scanner.apk")
                shutil.copyfile(APK_ARSENAL, target_dir / "BaDR-AI-Media-Arsenal.apk")


if __name__ == "__main__":
    build_apk()
