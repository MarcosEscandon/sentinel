rule Sentinel_Test_Marker {
    meta:
        id = "YARA-TEST-MARKER"
        severity = "low"
        description = "Marcador sintético para verificar la integración con YARA"
    strings:
        $marker = "SENTINEL_TEST_MARKER" ascii nocase
    condition:
        $marker
}
