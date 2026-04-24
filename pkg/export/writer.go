package export

import (
	"bufio"
	"bytes"
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
		file, err := os.Create(outputPath)
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
		results:    make([]models.SMBResult, 0),
	}, nil
}

type smbCSVWriter struct {
	outputPath string
	file       io.Writer
	closer     io.Closer
	csv        *csv.Writer
	results    []models.SMBResult
	mu         sync.Mutex
}

func (w *smbCSVWriter) WriteSMB(result models.SMBResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)

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

	if w.outputPath == "" {
		return w.closer.Close()
	}

	sort.Slice(w.results, func(i, j int) bool {
		ip1 := net.ParseIP(w.results[i].IP)
		ip2 := net.ParseIP(w.results[j].IP)
		return bytes.Compare(ip1, ip2) < 0
	})

	// Re-open file to overwrite with sorted results
	file, err := os.Create(w.outputPath)
	if err != nil {
		w.closer.Close()
		return err
	}
	defer file.Close()

	csvw := csv.NewWriter(file)
	if err := csvw.Write([]string{"ip", "hostname", "share", "path", "type"}); err != nil {
		w.closer.Close()
		return err
	}

	for _, result := range w.results {
		if err := csvw.Write([]string{
			result.IP,
			result.Hostname,
			result.Share,
			result.Path,
			result.Type,
		}); err != nil {
			csvw.Flush()
			w.closer.Close()
			return err
		}
	}
	csvw.Flush()
	if err := csvw.Error(); err != nil {
		w.closer.Close()
		return err
	}
	return w.closer.Close()
}

type csvWriter struct {
	outputPath string
	file       io.Writer
	closer     io.Closer
	csv        *csv.Writer
	results    []models.Result
	mu         sync.Mutex
}

func newCSVWriter(outputPath string) (Writer, error) {
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

	csvw := csv.NewWriter(w)
	if err := csvw.Write([]string{"ip", "hostname", "ports"}); err != nil {
		closer.Close()
		return nil, err
	}
	csvw.Flush()

	return &csvWriter{
		outputPath: outputPath,
		file:       w,
		closer:     closer,
		csv:        csvw,
		results:    make([]models.Result, 0),
	}, nil
}

func (w *csvWriter) Write(result models.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)

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
	w.csv.Flush()
	return w.csv.Error()
}

func (w *csvWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.outputPath == "" {
		return w.closer.Close()
	}

	sort.Slice(w.results, func(i, j int) bool {
		ip1 := net.ParseIP(w.results[i].IP)
		ip2 := net.ParseIP(w.results[j].IP)
		return bytes.Compare(ip1, ip2) < 0
	})

	// Re-open file to overwrite with sorted results
	file, err := os.Create(w.outputPath)
	if err != nil {
		w.closer.Close()
		return err
	}
	defer file.Close()

	csvw := csv.NewWriter(file)
	if err := csvw.Write([]string{"ip", "hostname", "ports"}); err != nil {
		w.closer.Close()
		return err
	}

	for _, result := range w.results {
		ports := make([]string, 0, len(result.Ports))
		for _, p := range result.Ports {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
		if err := csvw.Write([]string{
			result.IP,
			result.Hostname,
			strings.Join(ports, ";"),
		}); err != nil {
			csvw.Flush()
			w.closer.Close()
			return err
		}
	}
	csvw.Flush()
	if err := csvw.Error(); err != nil {
		w.closer.Close()
		return err
	}
	return w.closer.Close()
}

type jsonWriter struct {
	writer *bufio.Writer
	closer io.Closer
	first  bool
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
	return w.writer.Flush()
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
