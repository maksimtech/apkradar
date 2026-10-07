"""Real Android files for the tests: a binary AndroidManifest.xml, and an APK holding it.

Derived data: no APK is committed to this repository, so the ones the tests open
are written here, byte by byte, in the format aapt produces for a manifest — the
binary XML of frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h:
an RES_XML_TYPE header, a UTF-16 string pool, a resource map giving the system
attribute ids, then namespace and element chunks with typed attribute values.
The source is a plain XML string chosen by each test, and the attribute ids are
read from androguard's own copy of the platform's public.xml rather than typed
in here. What changes from an APK off a store is only what is left out: no DEX
unless a test adds one, no resources.arsc, no signature — none of which the code
under test reads.

These files are opened by the real androguard (`androguard.core.apk.APK`), so a
test that uses them runs androguard's parser, its AXMLPrinter and its get_xml()
— the very code whose return type a mock once hid (it returns bytes).
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

ANDROID_NS = "http://schemas.android.com/apk/res/android"

_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_RESOURCE_MAP_TYPE = 0x0180
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_NO_INDEX = 0xFFFFFFFF


def _split(name: str) -> tuple[str, str]:
    """`{uri}local` as ElementTree writes it, split into (uri, local)."""
    if name.startswith("{"):
        uri, local = name[1:].split("}", 1)
        return uri, local
    return "", name


def _string_pool(strings: list[str]) -> bytes:
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        encoded = s.encode("utf-16-le")
        if len(encoded) // 2 >= 0x8000:
            raise ValueError("string too long for the one-unit length form")
        data += struct.pack("<H", len(encoded) // 2) + encoded + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    return (
        struct.pack("<HHIIIIII", _RES_STRING_POOL_TYPE, header_size, strings_start + len(data),
                    len(strings), 0, 0, strings_start, 0)
        + b"".join(struct.pack("<I", o) for o in offsets)
        + bytes(data)
    )


def _node(chunk_type: int, body: bytes, line: int = 1) -> bytes:
    """An XML tree node chunk: 16-byte header (line number, no comment), then body."""
    return struct.pack("<HHIII", chunk_type, 16, 16 + len(body), line, _NO_INDEX) + body


def binary_xml(source: str) -> bytes:
    """`source`, a plain XML document, compiled to Android binary XML.

    Only the android namespace is declared, under the prefix `android`, which is
    what every manifest uses. A value made of digits only is stored as an
    integer, the way aapt stores versionCode or minSdkVersion; any other value is
    a string.
    """
    from androguard.core.resources import public

    system_ids = public.SYSTEM_RESOURCES["attributes"]["forward"]
    root = ET.fromstring(source)

    # aapt puts the attribute names that carry a resource id first in the pool,
    # in the order of the resource map that follows it.
    mapped: dict[str, None] = {}
    others: dict[str, None] = dict.fromkeys(["android", ANDROID_NS])
    for element in root.iter():
        for s in _split(element.tag):
            others[s] = None
        for name, value in element.attrib.items():
            uri, local = _split(name)
            if uri == ANDROID_NS and local in system_ids:
                mapped[local] = None
            else:
                others[local] = None
            if not value.isdigit():
                others[value] = None
    others.pop("", None)
    strings = list(mapped) + [s for s in others if s not in mapped]
    index = {s: i for i, s in enumerate(strings)}

    def ref(s: str) -> int:
        return index[s] if s else _NO_INDEX

    body = bytearray()
    body += _string_pool(strings)
    ids = [system_ids[s] for s in mapped]
    body += struct.pack("<HHI", _RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(ids))
    body += b"".join(struct.pack("<I", i) for i in ids)
    namespace = struct.pack("<II", ref("android"), ref(ANDROID_NS))
    body += _node(_RES_XML_START_NAMESPACE_TYPE, namespace)

    def element_chunks(element: ET.Element) -> None:
        uri, local = _split(element.tag)
        attributes = bytearray()
        for name, value in element.attrib.items():
            a_uri, a_local = _split(name)
            if value.isdigit():
                raw, kind, data = _NO_INDEX, _TYPE_INT_DEC, int(value)
            else:
                raw, kind, data = ref(value), _TYPE_STRING, ref(value)
            attributes += struct.pack("<IIIHBBI", ref(a_uri), ref(a_local), raw, 8, 0, kind, data)
        count = len(element.attrib)
        start = struct.pack("<IIHHHHHH", ref(uri), ref(local), 20, 20, count, 0, 0, 0)
        body.extend(_node(_RES_XML_START_ELEMENT_TYPE, start + attributes))
        for child in element:
            element_chunks(child)
        body.extend(_node(_RES_XML_END_ELEMENT_TYPE, struct.pack("<II", ref(uri), ref(local))))

    element_chunks(root)
    body += _node(_RES_XML_END_NAMESPACE_TYPE, namespace)
    return struct.pack("<HHI", _RES_XML_TYPE, 8, 8 + len(body)) + bytes(body)


def manifest(package: str, *, activities: tuple[str, ...] = (), hosts: tuple[str, ...] = ()) -> str:
    """The plain XML of a manifest: one activity per name, one deep link per host.

    A host is written as a character reference where XML would otherwise
    normalise it, so a CR/LF in one reaches the binary manifest as a CR/LF.
    """
    a = f'xmlns:android="{ANDROID_NS}"'
    links = "".join(
        f'<data android:scheme="https" android:host={quoteattr(h, {chr(13): "&#13;", chr(10): "&#10;"})}/>'
        for h in hosts
    )
    filters = f"<intent-filter>{links}</intent-filter>" if links else ""
    components = "".join(
        f'<activity android:name="{name}">{filters if i == 0 else ""}</activity>'
        for i, name in enumerate(activities or (f"{package}.MainActivity",))
    )
    return (
        f'<manifest {a} package="{package}" android:versionCode="1" android:versionName="1.0">'
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>'
        f'<application android:label="{package}">{components}</application>'
        "</manifest>"
    )


def write_apk(path: str | Path, manifest_xml: str) -> str:
    """An APK at `path` whose AndroidManifest.xml is `manifest_xml`, compiled."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", binary_xml(manifest_xml))
    return str(path)
