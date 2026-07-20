package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"goscanfast/pkg/export"
	"goscanfast/pkg/scanner"
	"goscanfast/pkg/tui"

	"github.com/spf13/cobra"
)

var version = "dev"

var (
	flagExclude         string
	flagPorts           string
	flagFormat          string
	flagOutput          string
	flagConcurrency     int
	flagTimeout         time.Duration
	flagTUI             bool
	flagPPS             int
	flagTargets         string
	flagPortConcurrency int
	flagRetries         int
)

var rootCmd = &cobra.Command{
	Use:     "goscanfast <cidr> [cidr...]",
	Short:   "High-speed TCP connect port scanner",
	Version: version,
	Args: func(cmd *cobra.Command, args []string) error {
		_, err := scanner.LoadTargetCIDRs(args, flagTargets)
		return err
	},
	RunE: func(cmd *cobra.Command, args []string) (retErr error) {
		cidrs, err := scanner.LoadTargetCIDRs(args, flagTargets)
		if err != nil {
			return err
		}

		ports, err := scanner.LoadPorts(flagPorts)
		if err != nil {
			return err
		}
		excludes, err := scanner.LoadExcludeCIDRs(flagExclude)
		if err != nil {
			return err
		}

		writer, err := export.NewWriter(flagFormat, flagOutput)
		if err != nil {
			return err
		}
		// Close flushes buffers and sorts the CSV; a failure here means
		// the results file may be incomplete, so it must surface.
		defer func() {
			if cerr := writer.Close(); cerr != nil && retErr == nil {
				retErr = fmt.Errorf("closing output: %w", cerr)
			}
		}()

		activityLogger, err := scanner.NewActivityLogger("activity.log", cidrs)
		if err != nil {
			return fmt.Errorf("failed to create activity.log: %w", err)
		}
		defer activityLogger.Close()

		var reporters scanner.MultiReporter
		reporters = append(reporters, activityLogger)

		var packetsSent atomic.Uint64

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		var tuiRunner *tui.Runner
		if flagTUI {
			if flagOutput == "" {
				fmt.Fprintln(os.Stderr, "tui disabled: use --output to avoid stdout conflicts")
			} else {
				total := scanner.TotalScannableHosts(cidrs, excludes)
				firstStart, firstEnd, _ := scanner.CIDRRange(cidrs[0])
				tuiRunner = tui.NewRunner(tui.Config{
					CIDR:        strings.Join(cidrs, ", "),
					RangeStart:  firstStart,
					RangeEnd:    firstEnd,
					Total:       total,
					Concurrency: flagConcurrency,
					PPS:         flagPPS,
					PacketsSent: &packetsSent,
					Cancel:      cancel,
				})
				if err := tuiRunner.Start(); err != nil {
					// No terminal (piped/headless): scan must not die
					// because the UI could not start.
					fmt.Fprintf(os.Stderr, "tui unavailable (%v); continuing without it\n", err)
				} else {
					reporters = append(reporters, tuiRunner.Reporter())
					defer tuiRunner.Stop()
				}
			}
		}

		engine := scanner.Engine{
			CIDRs:           cidrs,
			Exclude:         excludes,
			Ports:           ports,
			Concurrency:     flagConcurrency,
			PortConcurrency: flagPortConcurrency,
			Timeout:         flagTimeout,
			Retries:         flagRetries,
			Writer:          writer,
			Reporter:        reporters,
			PPS:             flagPPS,
			PacketsSent:     &packetsSent,
		}

		return engine.Run(ctx)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&flagExclude, "exclude", "", "Path to JSON file with CIDR ranges to exclude")
	rootCmd.Flags().StringVar(&flagPorts, "ports", "", "Path to JSON file with ports array or comma-separated list")
	rootCmd.Flags().StringVar(&flagFormat, "format", "csv", "Output format: csv or json")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Output file (default stdout)")
	rootCmd.Flags().IntVar(&flagConcurrency, "concurrency", 128, "Max concurrent workers")
	rootCmd.Flags().DurationVar(&flagTimeout, "timeout", 500*time.Millisecond, "Per-port timeout")
	rootCmd.Flags().BoolVar(&flagTUI, "tui", true, "Show TUI progress (requires --output)")
	rootCmd.Flags().IntVar(&flagPPS, "pps", 800, "Max packets per second, smoothly paced with no bursts (0=unlimited)")
	rootCmd.Flags().StringVar(&flagTargets, "targets", "", "Path to JSON file with CIDR targets")
	rootCmd.Flags().IntVar(&flagPortConcurrency, "port-concurrency", 0, "Max concurrent ports per host (0=auto)")
	rootCmd.Flags().IntVar(&flagRetries, "retries", 1, "Retries per port (0=disable)")

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}
