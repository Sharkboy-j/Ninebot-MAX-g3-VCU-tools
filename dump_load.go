package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadVerifiedDump(reader *bufio.Reader, prompt string) ([]byte, string) {
	defaultFile := findDefaultBinFile()
	promptLine := prompt
	if defaultFile != "" {
		promptLine = prompt + " [default: " + defaultFile + ", Tab to complete]"
	} else {
		promptLine = prompt + " [Tab to complete]"
	}
	fileName, err := readFileName(promptLine, defaultFile)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading filename:", err)
		os.Exit(1)
	}
	if fileName == "" {
		_, _ = fmt.Fprintln(os.Stderr, "❌ File not defined")
		os.Exit(1)
	}

	data, err := os.ReadFile(fileName)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error reading file:", err)
		os.Exit(1)
	}

	verifyFile(data, err, fileName)
	printDetectedVersion(data)
	return data, fileName
}

func patchedOutputPath(inputPath string) string {
	return inputPath + ".patched.bin"
}

func writePatchedDump(inputPath string, data []byte, reader *bufio.Reader) {
	outFile := patchedOutputPath(inputPath)
	inAbs, errIn := filepath.Abs(inputPath)
	outAbs, errOut := filepath.Abs(outFile)
	if errIn == nil && errOut == nil && strings.EqualFold(inAbs, outAbs) {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Refusing to overwrite the source dump")
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	err := os.WriteFile(outFile, data, 0644)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "❌ Error writing output file:", err)
		_, _ = reader.ReadString('\n')
		os.Exit(1)
	}
	fmt.Println("✅ All changes written to:", outFile)
	fmt.Println("(source file was not modified)")
	_, _ = reader.ReadString('\n')
}

func confirmYN(reader *bufio.Reader, prompt string) bool {
	fmt.Print(prompt)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y"
}
