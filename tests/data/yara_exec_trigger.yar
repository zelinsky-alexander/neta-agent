rule neta_exec_trigger_marker
{
    strings:
        $marker = "NETA_YARA_EXEC_TRIGGER_2026_09_03" ascii

    condition:
        $marker
}
