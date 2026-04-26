package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"goscanfast/pkg/export"
	"goscanfast/pkg/scanner"
	"goscanfast/pkg/tui"

	"github.com/spf13/cobra"
)

var (
	flagExclude     string
	flagPorts       string
	flagFormat      string
	flagOutput      string
	flagConcurrency int
	flagTimeout     time.Duration
	flagTUI         bool
	flagRate        int
	flagTargets     string
	flagPortConcurrency int
	flagRetries     int
)

var rootCmd = &cobra.Command{
	Use:   "goscanfast <cidr> [cidr...]",
	Short: "High-speed ICMP-first port scanner",
	Args: func(cmd *cobra.Command, args []string) error {
		_, err := scanner.LoadTargetCIDRs(args, flagTargets)
		return err
	},
	RunE: func(cmd *cobra.Command, args []string) error {
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
		defer writer.Close()

		var smbWriter export.SMBWriter
		for _, p := range ports {
			if p == 445 {
				var err error
				smbWriter, err = export.NewSMBCSVWriter("smb-results.csv")
				if err != nil {
					return fmt.Errorf("failed to create smb-results.csv: %w", err)
				}
				defer smbWriter.Close()
				break
			}
		}

		activityLogger, err := scanner.NewActivityLogger("activity.log", cidrs)
		if err != nil {
			return fmt.Errorf("failed to create activity.log: %w", err)
		}
		defer activityLogger.Close()

		var reporters scanner.MultiReporter
		reporters = append(reporters, activityLogger)

		var tuiRunner *tui.Runner
		if flagTUI {
			if flagOutput == "" {
				fmt.Fprintln(os.Stderr, "tui disabled: use --output to avoid stdout conflicts")
			} else {
				total := scanner.TotalCIDRSize(cidrs)
				firstStart, firstEnd, _ := scanner.CIDRRange(cidrs[0])
				tuiRunner = tui.NewRunner(tui.Config{
					CIDR:        strings.Join(cidrs, ", "),
					RangeStart:  firstStart,
					RangeEnd:    firstEnd,
					Total:       total,
					Concurrency: flagConcurrency,
				})
				reporters = append(reporters, tuiRunner.Reporter())
				if err := tuiRunner.Start(); err != nil {
					return err
				}
				defer tuiRunner.Stop()
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
			SMBWriter:       smbWriter,
			Reporter:        reporters,
			RateLimit:       flagRate,
		}

		return engine.Run()
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
	rootCmd.Flags().StringVar(&flagPorts, "ports", "", "Path to JSON file with ports array")
	rootCmd.Flags().StringVar(&flagFormat, "format", "csv", "Output format: csv or json")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Output file (default stdout)")
	rootCmd.Flags().IntVar(&flagConcurrency, "concurrency", 128, "Max concurrent workers")
	rootCmd.Flags().DurationVar(&flagTimeout, "timeout", 500*time.Millisecond, "Per-port timeout")
	rootCmd.Flags().BoolVar(&flagTUI, "tui", true, "Show TUI progress (requires --output)")
	rootCmd.Flags().IntVar(&flagRate, "rate", 1024, "Max scans per second (hosts/sec)")
	rootCmd.Flags().StringVar(&flagTargets, "targets", "", "Path to JSON file with CIDR targets")
	rootCmd.Flags().IntVar(&flagPortConcurrency, "port-concurrency", 0, "Max concurrent ports per host (0=auto)")
	rootCmd.Flags().IntVar(&flagRetries, "retries", 1, "Retries per port (0=disable)")

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}
