package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const version = "0.0.0‑dev" // <-- this will be auto‑replaced by CI

// --- Application Configuration & Branding ---
const (
	AppName         = "BTXS File Splitter"
	Author          = "BlackTechX011"
	GitHub          = "github.com/BlackTechX011"
	Version         = version
	DefaultPassword = "a-very-basic-but-functional-password"
	MagicString     = "BTXSv1"
	HeaderEndMarker = "---HEADER_END---"
	ChunkExtension  = ".btxs"
)

// --- Core Data Structures ---
type Header struct {
	FileID           string `json:"file_id"`
	OriginalFilename string `json:"original_filename"`
	OriginalFileHash string `json:"original_file_hash"`
	TotalChunks      int    `json:"total_chunks"`
	ChunkNumber      int    `json:"chunk_number"`
}

type chunkInfo struct {
	path   string
	header Header
}

// --- Main Application Logic with Cobra CLI ---

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "btxs",
		Version: Version,
		Short:   fmt.Sprintf("%s - A fast file splitter and merger by %s.", AppName, Author),
		Long: fmt.Sprintf(`%s (%s)

A command-line tool to split large files into smaller, encrypted chunks
and merge them back together seamlessly.

Features:
- Custom chunk naming and .btxs extension.
- Smart chunk detection for reliable merging.
- Data integrity verification using SHA256.

Developed by %s (%s).`, AppName, Version, Author, GitHub),
		SilenceUsage: true,
	}

	rootCmd.AddCommand(newSplitCmd())
	rootCmd.AddCommand(newMergeCmd())

	return rootCmd
}

// newSplitCmd creates the `split` subcommand with the new --name flag
func newSplitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "split --in <file> [flags]",
		Short: "Split a file into smaller, encrypted chunks",
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile, _ := cmd.Flags().GetString("in")
			outputDir, _ := cmd.Flags().GetString("out")
			chunkSizeStr, _ := cmd.Flags().GetString("size")
			outputName, _ := cmd.Flags().GetString("name") // Get the new custom name

			chunkSize, err := parseSize(chunkSizeStr)
			if err != nil {
				return fmt.Errorf("invalid chunk size format: %w", err)
			}
			if chunkSize <= 0 {
				return errors.New("chunk size must be a positive value")
			}

			// Pass the custom name to the split function
			return splitFile(inputFile, outputDir, chunkSize, outputName)
		},
	}

	cmd.Flags().StringP("in", "i", "", "Input file to split (required)")
	cmd.Flags().StringP("out", "o", ".", "Output directory for chunks")
	cmd.Flags().StringP("size", "s", "10MB", "Size of each chunk (e.g., 500KB, 10MB, 1GB)")
	cmd.Flags().StringP("name", "n", "", "Custom base name for output chunks (default: original filename)")
	cmd.MarkFlagRequired("in")

	return cmd
}

// newMergeCmd creates the `merge` subcommand
func newMergeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge .btxs chunks back into the original file",
		Long:  `Merge file chunks from a directory. The tool automatically finds all related .btxs chunks, verifies their integrity, and reassembles the original file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputDir, _ := cmd.Flags().GetString("dir")
			return mergeFiles(inputDir)
		},
	}

	cmd.Flags().StringP("dir", "d", ".", "Directory containing the .btxs chunks")
	return cmd
}

// --- Core Functionality: Splitting and Merging ---

// splitFile now accepts an outputName for custom chunk naming.
func splitFile(filePath, outputDir string, chunkSize int64, outputName string) error {
	fmt.Printf("▶ Starting split for: %s\n", filePath)
	fmt.Printf("  Chunk size: %s\n", formatSize(chunkSize))

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open source file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not get file stats: %w", err)
	}
	if fileInfo.Size() == 0 {
		return errors.New("input file is empty, nothing to split")
	}

	totalChunks := int(math.Ceil(float64(fileInfo.Size()) / float64(chunkSize)))
	fmt.Printf("  Total file size: %s | Total chunks: %d\n", formatSize(fileInfo.Size()), totalChunks)

	fmt.Println("⏳ Calculating original file hash (SHA256)...")
	originalHash, err := calculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate original file hash: %w", err)
	}
	fmt.Printf("  Hash: %s\n", originalHash)

	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return fmt.Errorf("could not create output directory: %w", err)
	}

	// Determine the base name for the output chunks
	var outputBaseName string
	if outputName != "" {
		outputBaseName = outputName // Use user-provided name
	} else {
		// Default to the original filename without its extension
		originalBase := filepath.Base(filePath)
		outputBaseName = strings.TrimSuffix(originalBase, filepath.Ext(originalBase))
	}
	fmt.Printf("  Output chunk base name: %s\n", outputBaseName)

	fileID := uuid.New().String()
	encryptionKey := generateKey(DefaultPassword)
	originalFilename := filepath.Base(filePath)
	reader := bufio.NewReader(file)

	for i := 1; i <= totalChunks; i++ {
		// New filename format: [basename].[number].btxs
		chunkFileName := fmt.Sprintf("%s.%04d%s", outputBaseName, i, ChunkExtension)
		chunkFilePath := filepath.Join(outputDir, chunkFileName)
		fmt.Printf("  Creating chunk %d/%d: %s\n", i, totalChunks, chunkFileName)

		header := Header{
			FileID: fileID, OriginalFilename: originalFilename, OriginalFileHash: originalHash,
			TotalChunks: totalChunks, ChunkNumber: i,
		}
		headerJSON, err := json.Marshal(header)
		if err != nil {
			return fmt.Errorf("failed to create header for chunk %d: %w", i, err)
		}

		chunkFile, err := os.Create(chunkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create chunk file %s: %w", chunkFilePath, err)
		}

		writer := bufio.NewWriter(chunkFile)
		writer.WriteString(MagicString + "\n")
		writer.Write(headerJSON)
		writer.WriteString("\n" + HeaderEndMarker + "\n")

		// --- More Efficient Encryption Logic ---
		buffer := make([]byte, chunkSize)
		bytesRead, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			chunkFile.Close()
			return fmt.Errorf("failed to read data for chunk %d: %w", i, err)
		}

		dataToWrite := buffer[:bytesRead]
		xorCipher(dataToWrite, encryptionKey) // Encrypt data in memory

		if _, err := writer.Write(dataToWrite); err != nil { // Write encrypted data
			chunkFile.Close()
			return fmt.Errorf("failed to write data to chunk %d: %w", i, err)
		}

		writer.Flush()
		chunkFile.Close()
	}

	fmt.Println("\n✅ Split operation completed successfully!")
	return nil
}

// mergeFiles now looks for the .btxs extension.
func mergeFiles(inputDir string) error {
	fmt.Printf("▶ Scanning directory for chunks: %s\n", inputDir)
	chunkGroups := make(map[string][]chunkInfo)
	files, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("could not read input directory: %w", err)
	}

	for _, file := range files {
		// Updated to find .btxs files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ChunkExtension) {
			continue
		}
		filePath := filepath.Join(inputDir, file.Name())
		header, err := readHeader(filePath)
		if err != nil {
			continue
		}
		chunkGroups[header.FileID] = append(chunkGroups[header.FileID], chunkInfo{path: filePath, header: *header})
	}

	if len(chunkGroups) == 0 {
		return errors.New("no valid " + ChunkExtension + " chunk files found in the directory")
	}
	fmt.Printf("  Found %d potential file(s) to merge.\n\n", len(chunkGroups))

	encryptionKey := generateKey(DefaultPassword)
	var mergeErrors []string

	for fileID, chunks := range chunkGroups {
		err := processMergeGroup(fileID, chunks, inputDir, encryptionKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error merging file %s: %v\n\n", chunks[0].header.OriginalFilename, err)
			mergeErrors = append(mergeErrors, chunks[0].header.OriginalFilename)
		}
	}

	if len(mergeErrors) > 0 {
		return fmt.Errorf("failed to merge the following files: %s", strings.Join(mergeErrors, ", "))
	}
	return nil
}

func processMergeGroup(fileID string, chunks []chunkInfo, inputDir string, encryptionKey []byte) error {
	firstHeader := chunks[0].header
	fmt.Printf("▶ Processing file: %s (ID: %s...)\n", firstHeader.OriginalFilename, fileID[:8])

	if len(chunks) != firstHeader.TotalChunks {
		return fmt.Errorf("missing chunks. Expected %d, found %d", firstHeader.TotalChunks, len(chunks))
	}

	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].header.ChunkNumber < chunks[j].header.ChunkNumber
	})

	outputFilePath := filepath.Join(filepath.Dir(inputDir), "merged_"+firstHeader.OriginalFilename)
	if _, err := os.Stat(outputFilePath); err == nil {
		return fmt.Errorf("output file %s already exists. Skipping to prevent overwrite", outputFilePath)
	}

	outFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("could not create output file %s: %w", outputFilePath, err)
	}
	defer outFile.Close()

	fmt.Println("  Assembling file and verifying integrity...")
	hasher := sha256.New()
	writer := bufio.NewWriter(outFile)

	for _, chunk := range chunks {
		fmt.Printf("    -> Merging chunk %d/%d\n", chunk.header.ChunkNumber, firstHeader.TotalChunks)
		data, err := readEncryptedData(chunk.path)
		if err != nil {
			os.Remove(outputFilePath)
			return fmt.Errorf("error reading data from chunk %s: %w. Aborting merge", chunk.path, err)
		}
		xorCipher(data, encryptionKey) // Decrypt in-place
		writer.Write(data)
		hasher.Write(data)
	}
	writer.Flush()

	reconstructedHash := hex.EncodeToString(hasher.Sum(nil))
	if reconstructedHash == firstHeader.OriginalFileHash {
		fmt.Printf("✅ Success! File '%s' reassembled and verified.\n\n", outputFilePath)
	} else {
		outFile.Close()
		os.Remove(outputFilePath)
		return fmt.Errorf("CRITICAL: Hash mismatch!\n  Expected: %s\n  Actual:   %s\n  The reassembled file is CORRUPTED and has been removed", firstHeader.OriginalFileHash, reconstructedHash)
	}
	return nil
}

// --- Helper & Utility Functions ---

func xorCipher(data []byte, key []byte) {
	keyLen := len(key)
	if keyLen == 0 {
		return
	}
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}
}

func generateKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func readHeader(filePath string) (*Header, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != MagicString {
		return nil, errors.New("not a valid chunk file")
	}
	var headerJSON []byte
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, errors.New("malformed header: could not find end marker")
		}
		if strings.TrimSpace(string(line)) == HeaderEndMarker {
			break
		}
		headerJSON = append(headerJSON, line...)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("could not parse header JSON: %w", err)
	}
	return &header, nil
}

func readEncryptedData(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	marker := []byte("\n" + HeaderEndMarker + "\n")
	idx := strings.Index(string(content), string(marker))
	if idx == -1 {
		return nil, errors.New("header end marker not found")
	}
	return content[idx+len(marker):], nil
}

func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0, errors.New("size string is empty")
	}
	upperSizeStr := strings.ToUpper(sizeStr)
	units := []struct{ Suffix string; Multiplier int64 }{
		{"GB", 1024 * 1024 * 1024}, {"MB", 1024 * 1024}, {"KB", 1024}, {"B", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(upperSizeStr, unit.Suffix) {
			numPart := strings.TrimSuffix(upperSizeStr, unit.Suffix)
			num, err := strconv.ParseFloat(numPart, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid number part: '%s'", numPart)
			}
			return int64(num * float64(unit.Multiplier)), nil
		}
	}
	return strconv.ParseInt(sizeStr, 10, 64)
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	const unit = 1024
	if bytes < unit*unit {
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(unit))
	}
	if bytes < unit*unit*unit {
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(unit*unit))
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/float64(unit*unit*unit))
}
