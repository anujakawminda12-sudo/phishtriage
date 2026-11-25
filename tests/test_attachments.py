"""Tests for attachments.py (week 2, step 8). Every test file here is harmless text."""

import importlib
import io
import sys
import zipfile

import pytest

from phishtriage import attachments
from phishtriage.attachments import (
    LIBMAGIC_MISSING,
    check_attachments,
    content_family,
    detect_type,
    extension,
    has_double_extension,
    inspect_bytes,
    is_type_mismatch,
    risky_reason,
)
from phishtriage.models import Attachment
from phishtriage.parser import parse_eml

# Tests that need the real libmagic are skipped where it is not installed
needs_libmagic = pytest.mark.skipif(attachments.magic is None, reason="libmagic not installed")

HTML = b"<html><body><p>Harmless PhishTriage test file. Not malware.</p></body></html>\n"
TEXT = b"Harmless PhishTriage test file. Not malware.\n"


def make_zip(names: list[str]) -> bytes:
    """A small, unencrypted ZIP built in memory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, TEXT)
    return buffer.getvalue()


def blank(filename: str) -> Attachment:
    return Attachment(filename=filename, content_type="", size=0, md5="", sha1="", sha256="")


def rules(findings) -> list[str]:
    return [finding.rule for finding in findings]


# --- file names ----------------------------------------------------------------------


def test_extension():
    assert extension("Invoice.PDF ") == "pdf"
    assert extension("archive.tar.gz") == "gz"
    assert extension("folder/inside.zip/report.docm") == "docm"
    assert extension("README") == ""
    assert extension(".bashrc") == ""


def test_risky_reason():
    assert risky_reason("Account_Review.html") == "a web page: fake login forms and HTML smuggling"
    assert risky_reason("setup.EXE") == "a program that runs when opened"
    assert risky_reason("budget.xlsm") == "an Office file with macros"
    assert risky_reason("disk.iso") is not None
    assert risky_reason("notes.txt") is None
    assert risky_reason("report.pdf") is None


def test_double_extension():
    assert has_double_extension("invoice.pdf.exe")
    assert has_double_extension("photo.jpg     .scr")  # spaces push .scr out of view
    assert has_double_extension("Payment_Details.pdf.js")
    assert not has_double_extension("report.2026.pdf")
    assert not has_double_extension("archive.tar.gz")
    assert not has_double_extension("Account_Review.html")
    assert not has_double_extension("my.notes.txt")


# --- real type vs name ---------------------------------------------------------------


def test_content_family():
    assert content_family("application/x-dosexec") == "executable"
    assert content_family("application/zip") == "archive"
    assert content_family("text/html") == "html"
    assert content_family("text/x-shellscript") == "script"
    assert content_family("application/pdf") == "other"
    assert content_family("") == "other"


def test_type_mismatch():
    assert is_type_mismatch("invoice.pdf", "text/html")  # a web page dressed up as a PDF
    assert is_type_mismatch("photo.jpg", "application/zip")  # an archive dressed up as a photo
    assert is_type_mismatch("update", "application/x-dosexec")  # a program with no extension
    assert not is_type_mismatch("report.docx", "application/zip")  # Office files are ZIPs
    assert not is_type_mismatch("page.html", "text/html")
    assert not is_type_mismatch("notes.txt", "text/plain")
    assert not is_type_mismatch("photo.jpg", "image/png")  # different, but not dangerous
    assert not is_type_mismatch("invoice.pdf", "")  # unknown real type: nothing to compare


@needs_libmagic
def test_detect_type_reads_the_content_not_the_name():
    assert detect_type(HTML) == "text/html"
    assert detect_type(b"%PDF-1.4\n%harmless\n") == "application/pdf"
    assert detect_type(make_zip(["a.txt"])) == "application/zip"
    assert detect_type(TEXT) == "text/plain"


def test_without_libmagic_nothing_crashes(monkeypatch):
    monkeypatch.setattr(attachments, "magic", None)
    defects: list[str] = []
    first, second = blank("invoice.pdf"), blank("photo.jpg")
    inspect_bytes(first, HTML, defects)
    inspect_bytes(second, HTML, defects)
    assert first.detected_type == ""
    assert defects == [LIBMAGIC_MISSING]  # reported once, not once per attachment


def test_missing_libmagic_is_handled_at_import(monkeypatch):
    # A None entry in sys.modules makes "import magic" raise ImportError, which is what
    # happens on a Mac before "brew install libmagic"
    monkeypatch.setitem(sys.modules, "magic", None)
    importlib.reload(attachments)
    try:
        assert attachments.magic is None
    finally:
        monkeypatch.undo()
        importlib.reload(attachments)  # put the real module back for the other tests


def test_libmagic_errors_mean_unknown_type(monkeypatch):
    class BrokenMagic:
        @staticmethod
        def from_buffer(data, mime):
            raise RuntimeError("simulated libmagic failure")

    monkeypatch.setattr(attachments, "magic", BrokenMagic)
    assert detect_type(HTML) == ""


# --- ZIP file lists ------------------------------------------------------------------


def test_zip_file_list_is_read_without_extracting():
    attachment = blank("docs.zip")
    defects: list[str] = []
    inspect_bytes(attachment, make_zip(["a.txt", "folder/b.pdf.exe"]), defects)
    assert attachment.archive_members == ["a.txt", "folder/b.pdf.exe"]
    assert attachment.encrypted is False
    assert defects in ([], [LIBMAGIC_MISSING])


def test_password_protected_zip_is_detected(fixtures):
    email = parse_eml(fixtures / "attachments_phish.eml")
    archive = next(att for att in email.attachments if att.filename == "Payment_Details.zip")
    assert archive.encrypted is True
    assert archive.archive_members == ["Payment_Details.pdf.js"]  # names are not hidden


def test_damaged_zip_is_a_defect_not_a_crash():
    data = make_zip(["a.txt"]).replace(b"PK\x01\x02", b"XX\x01\x02")  # break the file list
    attachment = blank("broken.zip")
    defects: list[str] = []
    inspect_bytes(attachment, data, defects)
    assert attachment.archive_members == []
    assert "Could not list broken.zip: BadZipFile" in defects


def test_huge_zip_is_not_listed(monkeypatch):
    monkeypatch.setattr(attachments, "MAX_ARCHIVE_BYTES", 10)
    attachment = blank("big.zip")
    defects: list[str] = []
    inspect_bytes(attachment, make_zip(["a.txt"]), defects)
    assert attachment.archive_members == []
    assert any("too large to list" in defect for defect in defects)


def test_file_named_zip_that_is_not_a_zip_is_a_defect():
    attachment = blank("fake.zip")
    defects: list[str] = []
    inspect_bytes(attachment, TEXT, defects)
    assert attachment.archive_members == []
    assert "Could not list fake.zip: BadZipFile" in defects


def test_normal_files_are_not_treated_as_zips():
    attachment = blank("notes.txt")
    defects: list[str] = []
    inspect_bytes(attachment, TEXT, defects)
    assert not any("Could not list" in defect for defect in defects)


# --- the check on whole emails -------------------------------------------------------


@needs_libmagic
def test_check_attachments_on_the_attachments_fixture(fixtures):
    findings = check_attachments(parse_eml(fixtures / "attachments_phish.eml"))
    assert rules(findings) == [
        "attachment_risky_type",
        "attachment_double_extension",
        "attachment_type_mismatch",
        "attachment_encrypted_archive",
    ]
    details = {finding.rule: finding.detail for finding in findings}
    assert details["attachment_risky_type"] == (
        "Statement.pdf.exe (a program that runs when opened); "
        "Payment_Details.zip contains Payment_Details.pdf.js (a script that runs when opened)"
    )
    assert details["attachment_double_extension"] == (
        "Statement.pdf.exe; Payment_Details.zip contains Payment_Details.pdf.js"
    )
    assert details["attachment_type_mismatch"] == (
        "Invoice_INV-2026-1142.pdf is named .pdf but its content is text/html"
    )
    assert "Terms.txt" not in " ".join(details.values())  # the harmless one is not mentioned


def test_check_attachments_on_other_fixtures(fixtures):
    paypal = check_attachments(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    assert rules(paypal) == ["attachment_risky_type"]
    assert paypal[0].detail.startswith("Account_Review.html (a web page")
    assert check_attachments(parse_eml(fixtures / "legit_newsletter.eml")) == []
    inner = parse_eml(fixtures / "forwarded_phish.eml").forwarded[0]
    assert check_attachments(inner) == []  # Password_Policy.txt is harmless
