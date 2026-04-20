package export

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}

	csvw := csv.NewWriter(bufio.NewWriter(file))
	if err := csvw.Write([]string{"ip", "hostname", "share", "path", "type"}); err != nil {
		file.Close()
		return nil, err
	}
	return &smbCSVWriter{writer: csvw, file: file}, nil
}

type smbCSVWriter struct {
	writer *csv.Writer
	file   *os.File
}

func (w *smbCSVWriter) WriteSMB(result models.SMBResult) error {
	if err := w.writer.Write([]string{
		result.IP,
		result.Hostname,
		result.Share,
		result.Path,
		result.Type,
	}); err != nil {
		return err
	}
	w.writer.Flush()
	return w.writer.Error()
}

func (w *smbCSVWriter) Close() error {
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		return err
	}
	return w.file.Close()
}

type csvWriter struct {
	writer *csv.Writer
	closer io.Closer
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

	csvw := csv.NewWriter(bufio.NewWriter(w))
	if err := csvw.Write([]string{"ip", "hostname", "ports"}); err != nil {
		closer.Close()
		return nil, err
	}
	return &csvWriter{writer: csvw, closer: closer}, nil
}

func (w *csvWriter) Write(result models.Result) error {
	ports := make([]string, 0, len(result.Ports))
	for _, p := range result.Ports {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	if err := w.writer.Write([]string{
		result.IP,
		result.Hostname,
		strings.Join(ports, ";"),
	}); err != nil {
		return err
	}
	w.writer.Flush()
	return w.writer.Error()
}

func (w *csvWriter) Close() error {
	if w.writer != nil {
		w.writer.Flush()
		if err := w.writer.Error(); err != nil {
			return err
		}
	}
	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
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
