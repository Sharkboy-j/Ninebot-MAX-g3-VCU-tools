package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func editCustom(reader *bufio.Reader) {
	sourceData, _ := readSourceDumpForCustom(reader)

	srcLay, err := findSecretKeyLayout(sourceData)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Source key:", err)
		os.Exit(1)
	}
	srcKey, err := readKeyAtOffsets(sourceData, srcLay)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Source key:", err)
		os.Exit(1)
	}

	data, templateName := readTargetTemplate(reader)

	fmt.Print("\nEnter new serial number (must be 14 characters like 1CGCC****C****): ")
	newSerial, _ := reader.ReadString('\n')
	newSerial = strings.ToUpper(strings.TrimSpace(newSerial))
	if len(newSerial) != serialLength {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Invalid serial number format")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	SetSn(data, newSerial, reader)

	if err := writeKeyAtSlots(data, mustFindVCUKeySlots(data), srcKey); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Key write:", err)
		os.Exit(1)
	}
	fmt.Printf("\n✅ Secret key copied from your dump (%d bytes)\n", len(srcKey))

	writePatchedDump(templateName, data, reader)
}

func mustFindVCUKeySlots(data []byte) secretKeyLayout {
	lay, err := findSecretKeyLayout(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Target key:", err)
		os.Exit(1)
	}
	return lay
}
