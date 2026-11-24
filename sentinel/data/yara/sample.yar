rule Sentinel_Test_Marker {
    meta:
        id = "YARA-TEST-MARKER"
        severity = "low"
        description = "Synthetic marker to verify YARA integration"
    strings:
        $marker = "SENTINEL_TEST_MARKER" ascii nocase
    condition:
        $marker
}
