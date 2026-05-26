package export

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"goscanfast/pkg/models"
)

type Writer interface {
	Write(models.Result) error
	Close() error
}

type SMBWriter interface {
	WriteSMB(models.SMBResult) error
	Close() error
}

func NewWriter(format, outputPath string) (Writer, error) {
	switch strings.ToLower(format) {
	case "csv":
		return newCSVWriter(outputPath)
	case "json":
		return newJSONWriter(outputPath)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func NewSMBCSVWriter(outputPath string) (SMBWriter, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer = io.NopCloser(nil)
	if outputPath != "" {
		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		w = file
		closer = file
	}

	csvw := csv.NewWriter(w)
	if err := csvw.Write([]string{"ip", "hostname", "share", "path", "type"}); err != nil {
		closer.Close()
		return nil, err
	}
	csvw.Flush()

	return &smbCSVWriter{
		outputPath: outputPath,
		file:       w,
		closer:     closer,
		csv:        csvw,
	}, nil
}

type smbCSVWriter struct {
	outputPath string
	file       io.Writer
	closer     io.Closer
	csv        *csv.Writer
	mu         sync.Mutex
}

func (w *smbCSVWriter) WriteSMB(result models.SMBResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.csv.Write([]string{
		result.IP,
		result.Hostname,
		result.Share,
		result.Path,
		result.Type,
	}); err != nil {
		return err
	}
	w.csv.Flush()
	return w.csv.Error()
}

func (w *smbCSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.csv.Flush()
	if err := w.csv.Error(); err != nil {
		w.closer.Close()
		return err
	}
	_ = w.closer.Close()

	if w.outputPath != "" {
		return sortCSV(w.outputPath)
	}
	return nil
}

type csvWriter struct {
	outputPath string
	file       io.Writer
	closer     io.Closer
	csv        *csv.Writer
	mu         sync.Mutex
	rowCount   int64
	done       chan struct{}
}

func newCSVWriter(outputPath string) (Writer, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer = io.NopCloser(nil)
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return nil, err
		}
		// Use buffered writer for file output
		w = bufio.NewWriterSize(file, 64*1024)
		closer = file
	}

	csvw := csv.NewWriter(w)
	if err := csvw.Write([]string{"ip", "hostname", "ports"}); err != nil {
		closer.Close()
		return nil, err
	}
	csvw.Flush()

	cw := &csvWriter{
		outputPath: outputPath,
		file:       w,
		closer:     closer,
		csv:        csvw,
		done:       make(chan struct{}),
	}

	if outputPath != "" {
		go cw.periodicFlush()
	}

	return cw, nil
}

func (w *csvWriter) Write(result models.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ports := make([]string, 0, len(result.Ports))
	for _, p := range result.Ports {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	if err := w.csv.Write([]string{
		result.IP,
		result.Hostname,
		strings.Join(ports, ";"),
	}); err != nil {
		return err
	}
	w.rowCount++
	if w.outputPath != "" && w.rowCount%1000 == 0 {
		w.flushLocked()
	}
	return nil
}

func (w *csvWriter) periodicFlush() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			w.flushLocked()
			w.mu.Unlock()
		case <-w.done:
			return
		}
	}
}

func (w *csvWriter) flushLocked() {
	w.csv.Flush()
	if bw, ok := w.file.(*bufio.Writer); ok {
		bw.Flush()
	}
}

func (w *csvWriter) Close() error {
	close(w.done)

	w.mu.Lock()
	defer w.mu.Unlock()

	w.flushLocked()

	_ = w.closer.Close()

	if w.outputPath != "" {
		return sortCSV(w.outputPath)
	}
	return nil
}

func sortCSV(path string) error {
	return externalSort(path)
}

type row struct {
	ip    uint32
	lines []string
}

func externalSort(path string) error {
	const chunkSize = 100000 // Adjust based on memory
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return err
	}

	var chunks []string
	for {
		var chunkData [][]string
		for i := 0; i < chunkSize; i++ {
			rec, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			chunkData = append(chunkData, rec)
		}
		if len(chunkData) == 0 {
			break
		}

		// Sort chunk
		// We need ipToUint32 but it's in scanner package. 
		// We'll use a local copy or net.ParseIP.
		sort.Slice(chunkData, func(i, j int) bool {
			return ipLess(chunkData[i][0], chunkData[j][0])
		})

		// Write chunk to tmp file
		cf, err := os.CreateTemp("", "goscanfast-chunk-*.csv")
		if err != nil {
			return err
		}
		cw := csv.NewWriter(cf)
		for _, r := range chunkData {
			_ = cw.Write(r)
		}
		cw.Flush()
		cf.Close()
		chunks = append(chunks, cf.Name())
	}

	// Merge chunks
	return mergeChunks(chunks, path, header)
}

func ipLess(ip1, ip2 string) bool {
	i1 := parseIP(ip1)
	i2 := parseIP(ip2)
	return i1 < i2
}

func parseIP(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func mergeChunks(chunks []string, outputPath string, header []string) error {
	defer func() {
		for _, c := range chunks {
			os.Remove(c)
		}
	}()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write(header)

	files := make([]*os.File, len(chunks))
	readers := make([]*csv.Reader, len(chunks))
	current := make([][]string, len(chunks))

	for i, c := range chunks {
		f, err := os.Open(c)
		if err != nil {
			return fmt.Errorf("failed to open chunk %s: %w", c, err)
		}
		files[i] = f
		readers[i] = csv.NewReader(files[i])
		rec, err := readers[i].Read()
		if err == nil {
			current[i] = rec
		}
	}

	for {
		minIdx := -1
		var minIP uint32
		for i, rec := range current {
			if rec == nil {
				continue
			}
			ip := parseIP(rec[0])
			if minIdx == -1 || ip < minIP {
				minIdx = i
				minIP = ip
			}
		}

		if minIdx == -1 {
			break
		}

		_ = w.Write(current[minIdx])
		rec, err := readers[minIdx].Read()
		if err != nil {
			current[minIdx] = nil
		} else {
			current[minIdx] = rec
		}
	}

	w.Flush()
	for _, f := range files {
		f.Close()
	}
	return nil
}

type jsonWriter struct {
	writer   *bufio.Writer
	closer   io.Closer
	first    bool
	rowCount int
}

func newJSONWriter(outputPath string) (Writer, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer = io.NopCloser(nil)
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return nil, err
		}
		w = file
		closer = file
	}

	bufw := bufio.NewWriter(w)
	if _, err := bufw.WriteString("["); err != nil {
		closer.Close()
		return nil, err
	}
	return &jsonWriter{writer: bufw, closer: closer, first: true}, nil
}

func (w *jsonWriter) Write(result models.Result) error {
	if w.writer == nil {
		return errors.New("writer not initialized")
	}
	if !w.first {
		if _, err := w.writer.WriteString(","); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := w.writer.Write(encoded); err != nil {
		return err
	}
	w.first = false
	w.rowCount++
	if w.rowCount%1000 == 0 {
		return w.writer.Flush()
	}
	return nil
}

func (w *jsonWriter) Close() error {
	if w.writer != nil {
		if _, err := w.writer.WriteString("]"); err != nil {
			return err
		}
		if err := w.writer.Flush(); err != nil {
			return err
		}
	}
	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
}
