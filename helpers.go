package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
	prefix             = "1CG"
	skipSerial         = "1CGC0000000001"
	serialLength       = 14
	vcuKeyAnchor       = "SCOOTER_VCU_"
	vcuKeySearchWindow = 512
	secretKeyLengthVCU = 22
	secretKeyTail0     = 0x30
	secretKeyTail1     = 0xB4
	secretKeyLegacyOff = 0x1F5B4
	secretKeyLegacyLen = 12
)

type secretKeyLayout struct {
	offsets []int
	length  int
}

func isVCUKeyByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func hasVCUKeyAnchor(data []byte) bool {
	anchor := []byte(vcuKeyAnchor)
	for i := 0; i <= len(data)-len(anchor); i++ {
		if bytes.Equal(data[i:i+len(anchor)], anchor) {
			return true
		}
	}
	return false
}

func findKeyStartInVCUWindowRelaxed(win []byte) int {
	for j := secretKeyLengthVCU; j+2 <= len(win); j++ {
		if win[j] != secretKeyTail0 || win[j+1] != secretKeyTail1 {
			continue
		}
		return j - secretKeyLengthVCU
	}
	return -1
}

func findVCUKeySlots(data []byte) (secretKeyLayout, error) {
	anchor := []byte(vcuKeyAnchor)
	seen := make(map[int]struct{})
	var offs []int
	for i := 0; i <= len(data)-len(anchor); i++ {
		if !bytes.Equal(data[i:i+len(anchor)], anchor) {
			continue
		}
		end := i + vcuKeySearchWindow
		if end > len(data) {
			end = len(data)
		}
		rel := findKeyStartInVCUWindowRelaxed(data[i:end])
		if rel < 0 {
			continue
		}
		abs := i + rel
		if _, dup := seen[abs]; dup {
			continue
		}
		seen[abs] = struct{}{}
		offs = append(offs, abs)
	}
	if len(offs) == 0 {
		return secretKeyLayout{}, fmt.Errorf("secret key not found (no %q slot with 30 B4 tail)", vcuKeyAnchor)
	}
	return secretKeyLayout{offsets: offs, length: secretKeyLengthVCU}, nil
}

func findSecretKeyLayout(data []byte) (secretKeyLayout, error) {
	if hasVCUKeyAnchor(data) {
		return findVCUKeySlots(data)
	}
	if len(data) < secretKeyLegacyOff+secretKeyLegacyLen {
		return secretKeyLayout{}, fmt.Errorf("secret key not found (no %q anchor and file too small for legacy key)", vcuKeyAnchor)
	}
	return secretKeyLayout{offsets: []int{secretKeyLegacyOff}, length: secretKeyLegacyLen}, nil
}

func isKeyAllFF(key []byte) bool {
	for _, b := range key {
		if b != 0xFF {
			return false
		}
	}
	return len(key) > 0
}

func printKeyInfo(key []byte, lay secretKeyLayout) {
	if lay.length == secretKeyLengthVCU && isKeyAllFF(key) {
		fmt.Print("\n🔑 Key: (erased, 0xFF × 22)")
	} else if lay.length == secretKeyLengthVCU && isASCIIKey(key) {
		fmt.Printf("\n🔑 Key (ASCII): %s", string(key))
	}
	fmt.Print("\n🔑 Key (hex): ")
	for _, b := range key {
		fmt.Printf("%02X ", b)
	}
	if lay.length == secretKeyLengthVCU && isKeyAllFF(key) == false {
		fmt.Printf("\n📦 Key (base64): %s", base64.StdEncoding.EncodeToString(key))
	}
	if len(lay.offsets) > 1 {
		fmt.Printf("\n📍 Key copies at offsets:")
		for _, o := range lay.offsets {
			fmt.Printf(" 0x%X", o)
		}
	} else {
		fmt.Printf("\n📍 Key offset: 0x%X", lay.offsets[0])
	}
}

func isASCIIKey(key []byte) bool {
	if len(key) != secretKeyLengthVCU {
		return false
	}
	for _, b := range key {
		if !isVCUKeyByte(b) {
			return false
		}
	}
	return true
}

func readKeyAtOffsets(buf []byte, lay secretKeyLayout) ([]byte, error) {
	if len(lay.offsets) == 0 {
		return nil, fmt.Errorf("no key offsets")
	}
	first := lay.offsets[0]
	if first+lay.length > len(buf) {
		return nil, fmt.Errorf("key out of bounds")
	}
	key := buf[first : first+lay.length]
	for _, o := range lay.offsets[1:] {
		if o+lay.length > len(buf) {
			return nil, fmt.Errorf("key copy out of bounds")
		}
		if !bytes.Equal(buf[o:o+lay.length], key) {
			return nil, fmt.Errorf("key copies under %q differ in file", vcuKeyAnchor)
		}
	}
	return key, nil
}

func writeKeyAtSlots(data []byte, lay secretKeyLayout, newKey []byte) error {
	if len(newKey) != lay.length {
		return fmt.Errorf("key length %d does not match slot length %d", len(newKey), lay.length)
	}
	for _, o := range lay.offsets {
		if o+lay.length > len(data) {
			return fmt.Errorf("write out of bounds at 0x%X", o)
		}
		copy(data[o:o+lay.length], newKey)
	}
	return nil
}

func parseManualKeyInput(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if len(input) == 44 {
		if isHexString(input) {
			key, err := hex.DecodeString(input)
			if err != nil {
				return nil, fmt.Errorf("invalid hex key: %w", err)
			}
			if len(key) != secretKeyLengthVCU {
				return nil, fmt.Errorf("hex key must decode to %d bytes", secretKeyLengthVCU)
			}
			return key, nil
		}
	}
	if len(input) != secretKeyLengthVCU {
		return nil, fmt.Errorf("key must be exactly %d ASCII characters or %d hex digits", secretKeyLengthVCU, secretKeyLengthVCU*2)
	}
	for i := 0; i < len(input); i++ {
		if !isVCUKeyByte(input[i]) {
			return nil, fmt.Errorf("invalid character at position %d (use A-Z, a-z, 0-9)", i+1)
		}
	}
	return []byte(input), nil
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func SetSn(data []byte, newSerial string, reader *bufio.Reader) {
	newSerial = strings.ToUpper(strings.TrimSpace(newSerial))
	if len(newSerial) != serialLength {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Invalid serial number format")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	count := 0
	for i := 0; i <= len(data)-serialLength; i++ {
		if bytes.Equal(data[i:i+3], []byte(prefix)) {
			sn := data[i : i+serialLength]
			if bytes.Equal(sn, []byte(skipSerial)) {
				i += serialLength - 1
				continue
			}
			copy(data[i:i+serialLength], newSerial)
			count++
			i += serialLength - 1
		}
	}
	if count == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ no serials replaced:")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	fmt.Printf("\n✅ Replaced %d serial number(s)\n", count)
}

func SetUidKey(data []byte, reader *bufio.Reader) {
	sourceName, err := readFileName("\nEnter source file name with original key: ", "")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Error reading filename:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	sourceData, err := os.ReadFile(sourceName)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Error reading source file:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	srcLay, err := findSecretKeyLayout(sourceData)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Source:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	tgtLay, err := findSecretKeyLayout(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Target:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	if srcLay.length != tgtLay.length {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ Key length mismatch: source %d vs target %d bytes\n", srcLay.length, tgtLay.length)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	newKey, err := readKeyAtOffsets(sourceData, srcLay)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Source key:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	fmt.Print("\n🔑 New key (hex): ")
	for _, b := range newKey {
		fmt.Printf("%02X ", b)
	}
	if isKeyAllFF(newKey) == false {
		fmt.Printf("\n📦 New key (base64): %s", base64.StdEncoding.EncodeToString(newKey))
	}

	if err := writeKeyAtSlots(data, tgtLay, newKey); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Printf("\n✅ Secret key written at %d location(s)\n", len(tgtLay.offsets))
}
