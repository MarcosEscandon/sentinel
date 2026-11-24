import json

from sentinel.engine.signatures import SignatureDatabase
from sentinel.feeds import detect_format, import_feed


def test_csv_import(tmp_path):
    source = tmp_path / "feed.csv"
    source.write_text(
        "type,value,severity,description,id\n"
        f"sha256,{'a' * 64},high,Prueba,HASH-1\n"
        "filename,.*\\.scr$,medium,SCR,FN-1\n"
        "content,MARCADOR,low,Contenido,CT-1\n",
        encoding="utf-8",
    )
    target = tmp_path / "signatures.json"

    report = import_feed(source, target, source="proveedor")

    assert report.added_hashes == 1
    assert report.added_filenames == 1
    assert report.added_content == 1
    assert report.revision == 1
    database = SignatureDatabase.load(target)
    assert database.revision == 1
    assert "a" * 64 in database.hashes

    again = import_feed(source, target, source="proveedor")
    assert again.duplicates == 3
    assert again.added_hashes == again.added_filenames == again.added_content == 0
    assert again.revision == 2


def test_misp_import(tmp_path):
    source = tmp_path / "misp.json"
    source.write_text(
        json.dumps(
            {
                "Event": {
                    "Attribute": [
                        {"type": "sha256", "value": "b" * 64, "comment": "misp hash"},
                        {"type": "filename", "value": ".*\\.exe$", "comment": "exe"},
                        {"type": "regexp", "value": "MARCADOR", "comment": "contenido"},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    target = tmp_path / "signatures.json"
    report = import_feed(source, target, source="misp")
    assert report.fmt == "misp"
    assert (report.added_hashes, report.added_filenames, report.added_content) == (1, 1, 1)


def test_plain_hash_list(tmp_path):
    source = tmp_path / "hashes.txt"
    source.write_text(f"# comentario\n{'c' * 64}\n\nno-es-un-hash\n", encoding="utf-8")
    target = tmp_path / "signatures.json"
    report = import_feed(source, target)
    assert report.fmt == "hashes"
    assert report.added_hashes == 1
    assert len(report.errors) == 0


def test_invalid_pattern_is_reported(tmp_path):
    source = tmp_path / "bad.csv"
    source.write_text("type,value\ncontent,[\n", encoding="utf-8")
    target = tmp_path / "signatures.json"
    report = import_feed(source, target)
    assert report.added_content == 0
    assert len(report.errors) == 1


def test_dry_run_does_not_write(tmp_path):
    source = tmp_path / "hashes.txt"
    source.write_text("d" * 64 + "\n", encoding="utf-8")
    target = tmp_path / "signatures.json"
    import_feed(source, target, dry_run=True)
    assert not target.exists()
    assert detect_format(source, source.read_text()) == "hashes"
