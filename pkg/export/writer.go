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

type csvWriter struct {
	outputPath string
	buf        *bufio.Writer
	closer     io.Closer
	csv        *csv.Writer
	mu         sync.Mutex
	rowCount   int64
	done       chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

func newCSVWriter(outputPath string) (Writer, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer = io.NopCloser(nil)
	if outputPath != "" {
		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		w = bufio.NewWriterSize(file, 64*1024)
		closer = file
	}

	csvw := csv.NewWriter(w)
	if err := csvw.Write([]string{"ip", "hostname", "ports"}); err != nil {
		closer.Close()
		return nil, err
	}
	csvw.Flush()
	if err := csvw.Error(); err != nil {
		closer.Close()
		return nil, err
	}

	cw := &csvWriter{
		outputPath: outputPath,
		closer:     closer,
		csv:        csvw,
		done:       make(chan struct{}),
	}
	if bw, ok := w.(*bufio.Writer); ok {
		cw.buf = bw
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
		return w.flushLocked()
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
			_ = w.flushLocked()
			w.mu.Unlock()
		case <-w.done:
			return
		}
	}
}

func (w *csvWriter) flushLocked() error {
	w.csv.Flush()
	if err := w.csv.Error(); err != nil {
		return err
	}
	if w.buf != nil {
		return w.buf.Flush()
	}
	return nil
}

// Close flushes and closes the output, then sorts a file-backed CSV by IP.
// It is safe to call more than once; only the first call has an effect.
func (w *csvWriter) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)

		w.mu.Lock()
		flushErr := w.flushLocked()
		closeErr := w.closer.Close()
		w.mu.Unlock()

		switch {
		case flushErr != nil:
			w.closeErr = flushErr
		case closeErr != nil:
			w.closeErr = closeErr
		case w.outputPath != "":
			w.closeErr = sortCSV(w.outputPath)
		}
	})
	return w.closeErr
}

func sortCSV(path string) error {
	return externalSort(path)
}

func externalSort(path string) error {
	const chunkSize = 100000
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	var chunks []string
	for {
		var chunkData [][]string
		for range chunkSize {
			rec, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("reading row: %w", err)
			}
			chunkData = append(chunkData, rec)
		}
		if len(chunkData) == 0 {
			break
		}

		sort.Slice(chunkData, func(i, j int) bool {
			return parseIP(chunkData[i][0]) < parseIP(chunkData[j][0])
		})

		cf, err := os.CreateTemp("", "goscanfast-chunk-*.csv")
		if err != nil {
			return err
		}
		cw := csv.NewWriter(cf)
		writeErr := error(nil)
		for _, r := range chunkData {
			if err := cw.Write(r); err != nil {
				writeErr = err
				break
			}
		}
		cw.Flush()
		if writeErr == nil {
			writeErr = cw.Error()
		}
		if cerr := cf.Close(); writeErr == nil {
			writeErr = cerr
		}
		if writeErr != nil {
			os.Remove(cf.Name())
			return fmt.Errorf("writing sort chunk: %w", writeErr)
		}
		chunks = append(chunks, cf.Name())
	}

	return mergeChunks(chunks, path, header)
}

// parseIP converts a dotted-quad string to uint32 for ordering.
// Unparseable input sorts first.
func parseIP(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func mergeChunks(chunks []string, outputPath string, header []string) (retErr error) {
	defer func() {
		for _, c := range chunks {
			os.Remove(c)
		}
	}()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); retErr == nil {
			retErr = cerr
		}
	}()

	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}

	files := make([]*os.File, 0, len(chunks))
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	readers := make([]*csv.Reader, 0, len(chunks))
	current := make([][]string, 0, len(chunks))

	for _, c := range chunks {
		cf, err := os.Open(c)
		if err != nil {
			return fmt.Errorf("failed to open chunk %s: %w", c, err)
		}
		files = append(files, cf)
		r := csv.NewReader(cf)
		readers = append(readers, r)
		rec, err := r.Read()
		if err != nil && err != io.EOF {
			return fmt.Errorf("reading chunk %s: %w", c, err)
		}
		current = append(current, rec)
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

		if err := w.Write(current[minIdx]); err != nil {
			return err
		}
		rec, err := readers[minIdx].Read()
		if err == io.EOF {
			current[minIdx] = nil
		} else if err != nil {
			return fmt.Errorf("reading chunk: %w", err)
		} else {
			current[minIdx] = rec
		}
	}

	w.Flush()
	return w.Error()
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
		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
