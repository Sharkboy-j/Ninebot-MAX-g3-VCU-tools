package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chzyer/readline"
)

func editOwn(verify *bool, reader *bufio.Reader) {
	data, fileName := loadVerifiedDump(reader, "Enter filename")

	changeSn(data, verify, reader)

	transferKey(data, reader)

	writePatchedDump(fileName, data, reader)
}

func verifyFile(data []byte, err error, fileName string) {
	if len(data) != 0x20000 {
		_, _ = fmt.Fprintln(os.Stderr, "❌ File corrupted")
		os.Exit(1)
	}
	fmt.Printf("✅ Len correct: %d\n", len(data))

	expected, err := hex.DecodeString(header[:len(header)-(len(header)%2)])
	if err != nil {
		panic("\n❌ invalid header signature. File corrupted: " + err.Error())
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

	if confirmYN(reader, "\nDo you want to update S/N? (Y/N): ") == false {
		return
	}

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

func transferKey(data []byte, reader *bufio.Reader) {
	lay, err := findSecretKeyLayout(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", err)
	} else {
		oldKey, rerr := readKeyAtOffsets(data, lay)
		if rerr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "❌ Key:", rerr)
		} else {
			printKeyInfo(oldKey, lay)
		}
	}

	if confirmYN(reader, "\nDo you want to transfer secret key from another file? (Y/N): ") == false {
		return
	}
	SetUidKey(data, reader)
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
		if len(d) == 0x20000 {
			printDetectedVersion(d)
		}
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
		printKeyInfo(oldKey, lay)
	}

	fmt.Println("\n✅ Press any key to exit")
}

func readFileName(promt, defaultFile string) (string, error) {
	if defaultFile == "" {
		defaultFile = findDefaultBinFile()
	}
	return readFileNameWithPaths(promt, defaultFile, collectBinPaths("."))
}

func readFileNameFromDir(promt, defaultFile, dir string) (string, error) {
	paths := getBinFiles(dir)
	if dir != "." {
		for i, f := range paths {
			paths[i] = dir + "/" + f
		}
	}
	return readFileNameWithPaths(promt, defaultFile, paths)
}

func readFileNameWithPaths(promt, defaultFile string, paths []string) (string, error) {
	var completerItems []readline.PrefixCompleterInterface
	for _, f := range paths {
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
	if dir == "." {
		return collectBinPaths(".")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var binFiles []string
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".bin") {
			binFiles = append(binFiles, name)
		}
	}
	sort.Strings(binFiles)
	return binFiles
}
