package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func printManualKeyHelp() {
	fmt.Println("\n--- Firmware key in dump (NOT CAN register 0xE4) ---")
	fmt.Println("Flash dump field: 22 bytes at file offsets 0x1420 and 0x10420 (both copies updated).")
	fmt.Println("Tail bytes 0x30 0xB4 after the key are left unchanged.")
	fmt.Println("CAN read_register 0xE4 (6-byte fragment) is runtime-only — do not enter it here.")
	fmt.Println("\nExamples (exactly 22 characters, A-Z a-z 0-9):")
	fmt.Println("  v9jlmfyhhh4y2w89lLqvsJ")
	fmt.Println("  mxstaeci1tj27zlbbRzd5m")
	fmt.Println("  1auj5gfmtc0ykb4ipybiFF")
	fmt.Println("\nOr 44 hex digits (22 bytes). For SHU Compat erasure use menu option 3.")
}

func editSetFirmwareKey(reader *bufio.Reader) {
	data, fileName := loadVerifiedDump(reader, "Enter dump filename")

	lay, err := findVCUKeySlots(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	oldKey, rerr := readKeyAtOffsets(data, lay)
	if rerr != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", rerr)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Println("\nCurrent key:")
	printKeyInfo(oldKey, lay)

	printManualKeyHelp()

	fmt.Print("\nEnter new key (22 chars) or hex (44 chars): ")
	input, _ := reader.ReadString('\n')
	newKey, err := parseManualKeyInput(input)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	fmt.Print("\nNew key (hex): ")
	for _, b := range newKey {
		fmt.Printf("%02X ", b)
	}
	if isASCIIKey(newKey) {
		fmt.Printf("\nNew key (ASCII): %s", string(newKey))
	}

	if confirmYN(reader, "\nWrite this key to the dump? (Y/N): ") == false {
		fmt.Println("No changes made.")
		_, _ = reader.ReadString('\n')
		return
	}

	if err := writeKeyAtSlots(data, lay, newKey); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Printf("\n✅ Key written at %d location(s)\n", len(lay.offsets))
	writePatchedDump(fileName, data, reader)
}

func readSourceDumpForCustom(reader *bufio.Reader) ([]byte, string) {
	fmt.Println("\nStep 1: Your current VCU dump (SN and key will be copied from it)")
	return loadVerifiedDump(reader, "Enter your dump filename")
}

func readTargetTemplate(reader *bufio.Reader) ([]byte, string) {
	fmt.Println("\nStep 2: Target firmware template from DUMPS/")
	dumps := getBinFiles("DUMPS")
	if len(dumps) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "❌ No .bin files in DUMPS/ directory")
		os.Exit(1)
	}
	path, err := readFileNameFromDir("Enter template file in DUMPS/: ", "", "DUMPS")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌", err)
		os.Exit(1)
	}
	if strings.HasPrefix(path, "DUMPS/") == false {
		path = "DUMPS/" + path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading template:", err)
		os.Exit(1)
	}
	if len(data) != 0x20000 {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Template file must be 128 KiB")
		os.Exit(1)
	}
	base := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		base = path[idx+1:]
	}
	return data, base
}
