package main

import (
	"encoding/binary"
	"fmt"
)

const (
	dumpVersionOffsetA = 0x1F02E
	dumpVersionOffsetB = 0x1F42E
)

func detectDumpVersion(data []byte) (version string, raw uint16, err error) {
	if len(data) < dumpVersionOffsetB+2 {
		return "", 0, fmt.Errorf("file too small for version field")
	}
	a := binary.LittleEndian.Uint16(data[dumpVersionOffsetA:])
	b := binary.LittleEndian.Uint16(data[dumpVersionOffsetB:])
	if a != b {
		return "", 0, fmt.Errorf("version fields mismatch (0x%04X vs 0x%04X)", a, b)
	}
	if a == 0 {
		return "", 0, fmt.Errorf("version field is zero")
	}
	ver, err := decodeVCUVersionNibbles(a)
	if err != nil {
		return "", a, err
	}
	return ver, a, nil
}

func decodeVCUVersionNibbles(raw uint16) (string, error) {
	d1 := (raw >> 8) & 0xF
	d2 := (raw >> 4) & 0xF
	d3 := raw & 0xF
	if d1 == 0 && d2 == 0 && d3 == 0 {
		return "", fmt.Errorf("invalid version nibbles 0x%04X", raw)
	}
	return fmt.Sprintf("%d.%d.%d", d1, d2, d3), nil
}

func printDetectedVersion(data []byte) {
	ver, raw, err := detectDumpVersion(data)
	if err != nil {
		fmt.Printf("\n⚠️  Could not detect VCU firmware version: %v\n", err)
		return
	}
	fmt.Printf("\n📌 Detected VCU firmware: %s (0x%04X)\n", ver, raw)
}
