package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var speedOffsets = []int{
	0x1F08D,
	0x1F091,
	0x1F48D,
	0x1F491,
}

const (
	prefix               = "1CG"
	skipSerial           = "1CGC0000000001"
	serialLength         = 14
	speedOffset1         = 0x0001F0C4
	speedOffset2         = 0x0001F4C4
	vcuKeyAnchor         = "SCOOTER_VCU_"
	vcuKeySearchWindow   = 512
	secretKeyLengthVCU   = 22
	secretKeyTail0       = 0x30
	secretKeyTail1       = 0xB4
	secretKeyLegacyOff   = 0x1F5B4
	secretKeyLegacyLen   = 12
)

type secretKeyLayout struct {
	offsets []int
	length  int
}

func isVCUKeyByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func findKeyStartInVCUWindow(win []byte) int {
	for j := secretKeyLengthVCU; j+2 <= len(win); j++ {
		if win[j] != secretKeyTail0 || win[j+1] != secretKeyTail1 {
			continue
		}
		keyStart := j - secretKeyLengthVCU
		ok := true
		for k := 0; k < secretKeyLengthVCU; k++ {
			if !isVCUKeyByte(win[keyStart+k]) {
				ok = false
				break
			}
		}
		if ok {
			return keyStart
		}
	}
	return -1
}

func findSecretKeyLayout(data []byte) (secretKeyLayout, error) {
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
		rel := findKeyStartInVCUWindow(data[i:end])
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
	if len(offs) > 0 {
		return secretKeyLayout{offsets: offs, length: secretKeyLengthVCU}, nil
	}
	if len(data) < secretKeyLegacyOff+secretKeyLegacyLen {
		return secretKeyLayout{}, fmt.Errorf("secret key not found (no %q + key before 30 B4, and file too small for legacy key)", vcuKeyAnchor)
	}
	return secretKeyLayout{offsets: []int{secretKeyLegacyOff}, length: secretKeyLegacyLen}, nil
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

func SetMileage(data []byte, mileageStr string, reader *bufio.Reader) {
	mileageVal, err := strconv.Atoi(mileageStr)
	if err != nil || mileageVal < 0 || mileageVal > 0xFFFF {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Invalid mileage value (must be 0–65535)")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	if err = writeUint16At(data, speedOffset1, uint16(mileageVal)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Error writing mileage")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	if err = writeUint16At(data, speedOffset2, uint16(mileageVal)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Error writing mileage")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	fmt.Printf("\n✅ Mileage 0x%04X written to both locations\n", mileageVal)
}

func SetSpeed(data []byte, speedStr string, reader *bufio.Reader) {
	speedVal, err := strconv.Atoi(speedStr)
	if err != nil || speedVal < 1 || speedVal > 125 {
		_, _ = fmt.Fprintln(os.Stderr, "\n❌ Invalid speed value (must be 1–99)")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}

	for _, offset := range speedOffsets {
		err = writeByteAt(data, offset, byte(speedVal))
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "\n❌ Failed to write speed value\n")
			_, _ = reader.ReadString('\n')
			os.Exit(1)
		}
	}

	fmt.Printf("\n✅ Speed 0x%02X written to all offsets\n", speedVal)
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

	fmt.Printf("\n📦 New key (base64): %s", base64.StdEncoding.EncodeToString(newKey))
	fmt.Print("\n🔑 New key (hex): ")
	for _, b := range newKey {
		fmt.Printf("%02X ", b)
	}

	for _, o := range tgtLay.offsets {
		if o+tgtLay.length > len(data) {
			_, _ = fmt.Fprintln(os.Stderr, "\n❌ Target write out of bounds")
			_, _ = reader.ReadString('\n')
			os.Exit(1)
		}
		copy(data[o:o+tgtLay.length], newKey)
	}
	fmt.Printf("\n✅ Secret key written at %d location(s)\n", len(tgtLay.offsets))
}

func writeUint16At(buf []byte, offset int, value uint16) error {
	if offset+2 > len(buf) {
		return fmt.Errorf("offset out of bounds")
	}
	binary.LittleEndian.PutUint16(buf[offset:], value)

	return nil
}
