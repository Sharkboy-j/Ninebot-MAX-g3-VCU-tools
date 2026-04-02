package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
)

func editOwn(verify *bool, reader *bufio.Reader) {
	fileName := ""
	defaultFile, err := findFirstBinFile()
	if defaultFile != "" {
		fileName, err = readFileName("Enter filename [default: "+defaultFile+"]: ", defaultFile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading filename:", err)
			os.Exit(1)
		}
	} else {
		fileName, err = readFileName("Enter filename: ", defaultFile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading filename:", err)
			os.Exit(1)
		}
	}

	if fileName == "" {
		_, _ = fmt.Fprintln(os.Stderr, "❌ File not defined:", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(fileName)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading file:", err)
		os.Exit(1)
	}

	verifyFile(data, err, fileName)

	changeSn(data, verify, reader)

	changeMileage(data, reader)

	changeSpeed(data, reader)

	transferKey(data, reader)

	outFile := fileName + ".patched.bin"
	err = os.WriteFile(outFile, data, 0644)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error writing output file:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Println("✅ All changes written to:", outFile)
	_, _ = reader.ReadString('\n')
}

func verifyFile(data []byte, err error, fileName string) {
	//verify length
	if len(data) != 0x20000 {
		_, _ = fmt.Fprintln(os.Stderr, "❌ File corrupted")
		os.Exit(1)
	}
	fmt.Printf("✅ Len correct: %d\n", len(data))

	//verif header
	expected, err := hex.DecodeString(header[:len(header)-(len(header)%2)])
	if err != nil {
		panic("\n❌ invalid header signature. File corrupted: " + err.Error())
		os.Exit(1)
	}

	valid, err := isDumpHeaderValid(fileName, expected)
	if err != nil {
		fmt.Println("\n❌ error:", err)
		os.Exit(1)
	}
	if valid {
		fmt.Println("\n✅ VALID header signature. Dump seems to be correct")
	} else {
		fmt.Println("\n❌ invalid header signature. File corrupted")
		os.Exit(1)
	}
}

func changeSn(data []byte, verify *bool, reader *bufio.Reader) {
	fmt.Println("\nFound serial numbers:")
	for i := 0; i <= len(data)-serialLength; i++ {
		if bytes.Equal(data[i:i+3], []byte(prefix)) {
			sn := data[i : i+serialLength]
			if bytes.Equal(sn, []byte(skipSerial)) {
				i += serialLength - 1
				continue
			}
			fmt.Printf("-> %s\n", string(sn))
			i += serialLength - 1
		}
	}

	if *verify {
		fmt.Println("\n✅ Verify done. No changes made. Press any key to exit")
		_, _ = reader.ReadString('\n')
		os.Exit(0)
	}

	fmt.Print("Do you want to update S/N? (Y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer == "y" {
		fmt.Print("Enter new serial number (must be 14 characters): ")
		newSerial, _ := reader.ReadString('\n')
		newSerial = strings.ToUpper(strings.TrimSpace(newSerial))
		if len(newSerial) != serialLength {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Invalid serial number format")
			_, _ = reader.ReadString('\n')
			os.Exit(1)
		}

		SetSn(data, newSerial, reader)
	}
}

func changeSpeed(data []byte, reader *bufio.Reader) {
	fmt.Println("🚀 Current speed values:")
	for _, offset := range speedOffsets {
		val, err := readByteAt(data, offset)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "❌ Failed to read speed value\n")
			continue
		}
		fmt.Printf("-> %d (0x%02X)\n", val, val)
	}

	fmt.Print("Do you want to update speed? (Y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer == "y" {
		fmt.Print("Enter new speed (1–125): ")
		speedStr, _ := reader.ReadString('\n')
		speedStr = strings.TrimSpace(speedStr)

		SetSpeed(data, speedStr, reader)
	}
}

func changeMileage(data []byte, reader *bufio.Reader) string {
	old1, _ := readUint16At(data, speedOffset1)
	old2, _ := readUint16At(data, speedOffset2)
	fmt.Printf("🚗 Current mileage A: %d (%.1f km)\n", old1, float64(old1)/10.0)
	fmt.Printf("🚗 Current mileage B: %d (%.1f km)\n", old2, float64(old2)/10.0)

	fmt.Print("Do you want to update mileage? (Y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer == "y" {
		fmt.Print("Enter new mileage (0–65535): ")
		mileageStr, _ := reader.ReadString('\n')
		mileageStr = strings.TrimSpace(mileageStr)

		SetMileage(data, mileageStr, reader)
	}

	return answer
}

func transferKey(data []byte, reader *bufio.Reader) {
	lay, err := findSecretKeyLayout(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", err)
	} else {
		oldKey, rerr := readKeyAtOffsets(data, lay)
		if rerr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", rerr)
		} else {
			fmt.Print("🔑 Old key (hex): ")
			for _, b := range oldKey {
				fmt.Printf("%02X ", b)
			}
			fmt.Printf("\n📦 Old key (base64): %s", base64.StdEncoding.EncodeToString(oldKey))
			if len(lay.offsets) > 1 {
				fmt.Printf("\n📍 Key copies at offsets:")
				for _, o := range lay.offsets {
					fmt.Printf(" 0x%X", o)
				}
			} else {
				fmt.Printf("\n📍 Key offset: 0x%X", lay.offsets[0])
			}
		}
	}

	fmt.Print("\nDo you want to transfer secret key from another file? (Y/N): ")
	transfer, _ := reader.ReadString('\n')
	transfer = strings.ToLower(strings.TrimSpace(transfer))

	if transfer == "y" {
		SetUidKey(data, reader)
	}
}

func printKeys() {
	binFiles := getBinFiles(".")
	for _, f := range binFiles {
		d, err := os.ReadFile(f)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading file:", err)
			os.Exit(1)
		}
		fmt.Printf("\n\n%s", f)
		lay, err := findSecretKeyLayout(d)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "\n❌ Key:", err)
			continue
		}
		oldKey, rerr := readKeyAtOffsets(d, lay)
		if rerr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "\n❌ Key:", rerr)
			continue
		}
		fmt.Print("\n🔑 Old key (hex): ")
		for _, b := range oldKey {
			fmt.Printf("%02X ", b)
		}
		fmt.Printf("\n📦 Old key (base64): %s", base64.StdEncoding.EncodeToString(oldKey))
		if len(lay.offsets) > 1 {
			fmt.Printf("\n📍 Offsets:")
			for _, o := range lay.offsets {
				fmt.Printf(" 0x%X", o)
			}
		} else {
			fmt.Printf("\n📍 Offset: 0x%X", lay.offsets[0])
		}
	}

	fmt.Println("\n✅ Press any key to exit")
}

func readFileName(promt, defaultFile string) (string, error) {
	binFiles := getBinFiles(".")
	var completerItems []readline.PrefixCompleterInterface
	for _, f := range binFiles {
		completerItems = append(completerItems, readline.PcItem(f))
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          promt,
		AutoComplete:    readline.NewPrefixCompleter(completerItems...),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		panic(err)
	}
	defer func(rl *readline.Instance) {
		_ = rl.Close()
	}(rl)

	line, err := rl.Readline()
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	if len(line) == 0 {
		line = defaultFile
	}

	fmt.Println("You selected:", strings.TrimSpace(line))
	return strings.TrimSpace(line), nil
}

func getBinFiles(dir string) []string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var binFiles []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(strings.ToLower(f.Name()), ".bin") {
			binFiles = append(binFiles, f.Name())
		}
	}
	return binFiles
}

func readByteAt(buf []byte, offset int) (byte, error) {
	if offset >= len(buf) {
		return 0, fmt.Errorf("offset out of bounds")
	}
	return buf[offset], nil
}

func writeByteAt(buf []byte, offset int, value byte) error {
	if offset >= len(buf) {
		return fmt.Errorf("offset out of bounds")
	}
	buf[offset] = value
	return nil
}

func findFirstBinFile() (string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".bin") {
			return entry.Name(), nil
		}
	}
	return "", fmt.Errorf("no .bin file found in current directory")
}

func readUint16At(buf []byte, offset int) (uint16, error) {
	if offset+2 > len(buf) {
		return 0, fmt.Errorf("offset out of bounds")
	}
	return binary.LittleEndian.Uint16(buf[offset : offset+2]), nil
}
