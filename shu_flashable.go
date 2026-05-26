package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
)

func editMakeFlashableSHU(reader *bufio.Reader) {
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
	printKeyInfo(oldKey, lay)

	if isKeyAllFF(oldKey) {
		fmt.Println("\n✅ Dump is already flashable with SHU (key is 0xFF × 22). No changes written.")
		_, _ = reader.ReadString('\n')
		return
	}

	fmt.Println("\nThis will replace the 22-byte firmware key with 0xFF at offsets 0x1420 and 0x10420.")
	fmt.Println("Use this before flashing SHU Compat firmware that expects an empty key slot.")
	if confirmYN(reader, "\nMake this dump flashable with SHU? (Y/N): ") == false {
		fmt.Println("No changes made.")
		_, _ = reader.ReadString('\n')
		return
	}

	ffKey := bytes.Repeat([]byte{0xFF}, lay.length)
	if err := writeKeyAtSlots(data, lay, ffKey); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Printf("\n✅ Key erased (0xFF × 22) at %d location(s)\n", len(lay.offsets))
	writePatchedDump(fileName, data, reader)
}
