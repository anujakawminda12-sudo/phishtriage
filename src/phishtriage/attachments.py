"""Attachment metadata and checks (week 2, step 8).

Safety: nothing here opens, extracts or runs a file. libmagic reads the first bytes of
the content (its "magic number"), and for a ZIP only the file list at the end of the
archive is read. Nothing is decompressed, so a "ZIP bomb" cannot hurt us, and a password-
protected ZIP still shows its file names (ZIP encryption does not hide them).

inspect_bytes() is called by the parser and fills in Attachment.detected_type,
archive_members and encrypted. check_attachments() turns that into Finding objects.
"""

from __future__ import annotations

import io
import zipfile

from .models import Attachment, Finding, ParsedEmail

try:
    import magic  # python-magic: a wrapper around the libmagic C library
except ImportError:  # libmagic is not installed (macOS: brew install libmagic)
    magic = None

LIBMAGIC_MISSING = "File type detection unavailable: libmagic is not installed"

# Every ZIP entry starts with this "local file header" signature: the letters PK, then 3, 4
ZIP_SIGNATURE = b"PK\x03\x04"
UNKNOWN_BINARY = "application/octet-stream"  # libmagic's answer for "data I do not know"

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # larger ZIPs are not listed
MAX_MEMBERS_KEPT = 100  # file names kept per archive

# Extensions that are dangerous to open, with the reason shown in the finding.
RISKY_EXTENSIONS: dict[str, str] = {
    **dict.fromkeys(
        ("exe", "scr", "com", "pif", "msi", "msp", "dll", "cpl", "jar", "appx", "msix", "xll"),
        "a program that runs when opened",
    ),
    **dict.fromkeys(
        ("js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "bat", "cmd"),
        "a script that runs when opened",
    ),
    **dict.fromkeys(("lnk", "url", "scf", "library-ms"), "a shortcut that can launch programs"),
    **dict.fromkeys(
        ("iso", "img", "vhd", "vhdx"), "a disk image, often used to slip past Mark-of-the-Web"
    ),
    **dict.fromkeys(
        ("html", "htm", "shtml", "xhtml", "svg"),
        "a web page: fake login forms and HTML smuggling",
    ),
    **dict.fromkeys(
        ("docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"),
        "an Office file with macros",
    ),
    **dict.fromkeys(("one", "chm"), "a file type abused to deliver malware"),
}

# Harmless-looking extensions that attackers put in front of a risky one: invoice.pdf.exe
DECOY_EXTENSIONS = frozenset(
    "pdf doc docx xls xlsx ppt pptx txt rtf csv jpg jpeg png gif bmp tif tiff "
    "mp3 mp4 mov wav zip rar".split()
)

# What the real content (from libmagic) can be, grouped into families.
EXECUTABLE_TYPES = frozenset(
    {
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
        "application/x-msdownload",
        "application/x-executable",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/x-msi",
    }
)
ARCHIVE_TYPES = frozenset(
    {
        "application/zip",
        "application/x-rar",
        "application/vnd.rar",
        "application/x-7z-compressed",
        "application/x-iso9660-image",
        "application/gzip",
        "application/x-tar",
        "application/vnd.ms-cab-compressed",
    }
)
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
SCRIPT_TYPES = frozenset(
    {"text/x-shellscript", "application/javascript", "text/javascript", "text/x-msdos-batch"}
)

# The family each extension claims to be. Office Open XML files are ZIPs inside, so a ZIP
# with one of those extensions is normal.
EXTENSION_FAMILIES: dict[str, str] = {
    **dict.fromkeys(("exe", "scr", "com", "pif", "msi", "msp", "dll", "cpl"), "executable"),
    **dict.fromkeys(("zip", "rar", "7z", "iso", "img", "gz", "tgz", "tar", "cab"), "archive"),
    **dict.fromkeys(("html", "htm", "shtml", "xhtml"), "html"),
    **dict.fromkeys(("js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "sh", "hta"), "script"),
    **dict.fromkeys(
        "docx docm dotx dotm xlsx xlsm xltx xltm pptx pptm potx potm odt ods odp jar apk "
        "appx msix epub".split(),
        "zip-based",
    ),
}


# --- metadata, filled in by the parser -----------------------------------------------


def inspect_bytes(attachment: Attachment, data: bytes, defects: list[str]) -> None:
    """Fill in detected_type, archive_members and encrypted for one attachment.

    Problems (no libmagic, a broken ZIP) are added to `defects` instead of raising.
    """
    attachment.detected_type = detect_type(data)
    if magic is None and LIBMAGIC_MISSING not in defects:
        defects.append(LIBMAGIC_MISSING)

    if attachment.detected_type == "application/zip" or extension(attachment.filename) == "zip":
        _read_zip_listing(attachment, data, defects)


def detect_type(data: bytes) -> str:
    """The real MIME type, read by libmagic from the content, or "" if unavailable.

    One correction (GitHub phase): libmagic 5.46 (Ubuntu 26.04, Debian 13, Alpine 3.21)
    answers "application/octet-stream" for a ZIP read from memory, a known libmagic bug
    (bugs.astron.com issue 622). A ZIP starts with ZIP_SIGNATURE, so that one answer is
    corrected to "application/zip"; every other answer is kept exactly as libmagic gave
    it. Without the correction, a ZIP named photo.jpg would not count as an archive in
    disguise, and its file list would not be read.
    """
    if magic is None:
        return ""
    try:
        found = magic.from_buffer(data, mime=True)
    except Exception:  # libmagic can fail on odd input; the type is then simply unknown
        return ""
    if found == UNKNOWN_BINARY and data.startswith(ZIP_SIGNATURE):
        return "application/zip"
    return found


def _read_zip_listing(attachment: Attachment, data: bytes, defects: list[str]) -> None:
    """Read a ZIP's file list (its "central directory") without extracting anything.

    Called for anything named .zip or detected as a ZIP. If the list cannot be read (a
    damaged ZIP, or a file named .zip that is not one), that is recorded as a defect.
    There is deliberately no zipfile.is_zipfile() check first: it answers differently on
    Python 3.13 and 3.15 for a damaged ZIP, while opening the archive fails on both.
    """
    if len(data) > MAX_ARCHIVE_BYTES:
        defects.append(f"{attachment.filename}: ZIP too large to list ({len(data)} bytes)")
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()  # reads names and flags only; nothing is unpacked
    except Exception as exc:  # a damaged or hostile archive must not stop the analysis
        defects.append(f"Could not list {attachment.filename}: {type(exc).__name__}")
        return
    attachment.archive_members = [entry.filename for entry in entries[:MAX_MEMBERS_KEPT]]
    # Bit 0 of a ZIP entry's flags means "this file is encrypted" (ZipCrypto or AES)
    attachment.encrypted = any(entry.flag_bits & 0x1 for entry in entries)


# --- small helpers -------------------------------------------------------------------


def extension(filename: str) -> str:
    """The last extension, lower-case, without the dot: "Invoice.PDF " -> "pdf"."""
    name = filename.strip().rpartition("/")[2]  # archive members can have folders
    stem, dot, ext = name.rpartition(".")
    return ext.strip().lower() if dot and stem else ""


def risky_reason(filename: str) -> str | None:
    """Why this file type is dangerous, or None if it is not on the list."""
    return RISKY_EXTENSIONS.get(extension(filename))


def has_double_extension(filename: str) -> bool:
    """True for a risky extension hidden behind a harmless-looking one.

    "invoice.pdf.exe", "photo.jpg   .scr" (spaces push .scr out of view) -> True
    "report.2026.pdf", "archive.tar.gz", "Account_Review.html"           -> False
    """
    parts = filename.strip().rpartition("/")[2].lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-1].strip() in RISKY_EXTENSIONS and parts[-2].strip() in DECOY_EXTENSIONS


def content_family(mime: str) -> str:
    """Group a libmagic MIME type: executable, archive, html, script or other."""
    if mime in EXECUTABLE_TYPES:
        return "executable"
    if mime in ARCHIVE_TYPES:
        return "archive"
    if mime in HTML_TYPES:
        return "html"
    if mime in SCRIPT_TYPES:
        return "script"
    return "other"


def is_type_mismatch(filename: str, detected_type: str) -> bool:
    """True when the content is dangerous (a program, archive, web page or script) but
    the file name claims to be something else.

        ("invoice.pdf", "text/html")        -> True   (a web page dressed up as a PDF)
        ("photo.jpg", "application/zip")    -> True   (an archive dressed up as a photo)
        ("report.docx", "application/zip")  -> False  (Office files are ZIPs inside)
        ("notes.txt", "text/plain")         -> False  (harmless content)

    Other differences (a .jpg that is really a PNG) are not dangerous, so not reported.
    """
    found = content_family(detected_type)
    if found == "other":
        return False
    claimed = EXTENSION_FAMILIES.get(extension(filename), "other")
    if found == "archive" and claimed == "zip-based":
        return False
    return claimed != found


# --- the check -----------------------------------------------------------------------


def check_attachments(email: ParsedEmail) -> list[Finding]:
    """One Finding per rule, listing every attachment (or file inside a ZIP) it applies to.

    Rules:
      attachment_risky_type         a dangerous file type (.exe, .js, .html, .iso, .docm, ...)
      attachment_double_extension   a risky extension hidden behind a harmless one
      attachment_type_mismatch      the content is dangerous but the name says otherwise
      attachment_encrypted_archive  a password-protected ZIP: scanners cannot see inside
    """
    hits: dict[str, list[str]] = {
        "attachment_risky_type": [],
        "attachment_double_extension": [],
        "attachment_type_mismatch": [],
        "attachment_encrypted_archive": [],
    }

    for att in email.attachments:
        # The attachment itself, then every file listed inside it (if it is a ZIP)
        names = [(att.filename, att.filename)]
        names += [(f"{att.filename} contains {member}", member) for member in att.archive_members]
        for label, name in names:
            reason = risky_reason(name)
            if reason:
                hits["attachment_risky_type"].append(f"{label} ({reason})")
            if has_double_extension(name):
                hits["attachment_double_extension"].append(label)

        if is_type_mismatch(att.filename, att.detected_type):
            hits["attachment_type_mismatch"].append(
                f"{att.filename} is named .{extension(att.filename) or '(none)'} "
                f"but its content is {att.detected_type}"
            )
        if att.encrypted:
            hits["attachment_encrypted_archive"].append(
                f"{att.filename} is password-protected, so scanners cannot check what is inside"
            )

    return [Finding(rule=rule, detail="; ".join(items)) for rule, items in hits.items() if items]
