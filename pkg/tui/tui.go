package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goscanfast/pkg/models"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Config struct {
	CIDR        string
	RangeStart  string
	RangeEnd    string
	Total       uint64
	Concurrency int
}

type Runner struct {
	app    *tview.Application
	config Config

	enqueued  uint64
	inFlight  uint64
	completed uint64
	alive      uint64
	found      uint64

	rateEMA   float64
	lastTick  time.Time
	lastCount uint64

	portMu    sync.Mutex
	portLines []string
	liveMu    sync.Mutex
	liveLines []string

	header    *tview.TextView
	target    *tview.TextView
	stats     *tview.TextView
	progress  *tview.TextView
	ports     *tview.TextView
	footer    *tview.TextView

	stopOnce sync.Once
}

type Reporter struct {
	runner *Runner
}

func NewRunner(cfg Config) *Runner {
	r := &Runner{config: cfg}
	r.app = tview.NewApplication()
	r.header = tview.NewTextView().SetDynamicColors(true)
	r.header.SetBorder(false)
	r.header.SetText(headerArt())

	r.target = tview.NewTextView().SetDynamicColors(true)
	r.target.SetBorder(true).SetTitle("Target Info")

	r.stats = tview.NewTextView().SetDynamicColors(true)
	r.stats.SetBorder(true).SetTitle("Statistics")

	r.progress = tview.NewTextView().SetDynamicColors(true)
	r.progress.SetBorder(true).SetTitle("Progress")

	r.ports = tview.NewTextView().SetDynamicColors(true)
	r.ports.SetBorder(true).SetTitle("Live Discovery")

	r.footer = tview.NewTextView().SetDynamicColors(true)
	r.footer.SetBorder(false)
	r.footer.SetText("Legend: q=quit, Ctrl+C=quit")

	grid := tview.NewGrid()
	grid.SetRows(6, 5, 7, 0, 1)
	grid.SetColumns(0, 0)
	grid.SetBorders(false)
	grid.AddItem(r.header, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(r.target, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(r.stats, 1, 1, 1, 1, 0, 0, false)
	grid.AddItem(r.progress, 2, 0, 1, 2, 0, 0, false)
	grid.AddItem(r.ports, 3, 0, 1, 2, 0, 0, false)
	grid.AddItem(r.footer, 4, 0, 1, 2, 0, 0, false)

	r.app.SetRoot(grid, true)
	r.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || event.Rune() == 'q' {
			r.Stop()
			return nil
		}
		return event
	})

	return r
}

func (r *Runner) Reporter() *Reporter {
	return &Reporter{runner: r}
}

func (r *Runner) Start() error {
	r.lastTick = time.Now()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			r.updateRate()
			r.refresh()
		}
	}()
	go func() {
		_ = r.app.Run()
	}()
	return nil
}

func (r *Runner) Stop() {
	r.stopOnce.Do(func() {
		r.app.Stop()
	})
}

func (rep *Reporter) OnStart(total uint64) {
	_ = total
}

func (rep *Reporter) OnHostEnqueued() {
	atomic.AddUint64(&rep.runner.enqueued, 1)
}

func (rep *Reporter) OnHostStart(ip string) {
	atomic.AddUint64(&rep.runner.inFlight, 1)
	rep.runner.addLiveLine(ip, "Scanning...")
}

func (rep *Reporter) OnHostDone() {
	atomic.AddUint64(&rep.runner.completed, 1)
	atomic.AddUint64(&rep.runner.inFlight, ^uint64(0))
}

func (rep *Reporter) OnPortOpen(ip string, port int) {
	line := fmt.Sprintf("%s:%d", ip, port)
	rep.runner.portMu.Lock()
	rep.runner.portLines = append([]string{line}, rep.runner.portLines...)
	if len(rep.runner.portLines) > 20 {
		rep.runner.portLines = rep.runner.portLines[:20]
	}
	rep.runner.portMu.Unlock()

	atomic.AddUint64(&rep.runner.found, 1)
}

func (rep *Reporter) OnResult(result models.Result) {
	_ = result
	atomic.AddUint64(&rep.runner.alive, 1)
	rep.runner.addLiveLine(result.IP, formatResultLine(result))
}

func (rep *Reporter) OnDone() {
	rep.runner.refresh()
}

func (r *Runner) updateRate() {
	now := time.Now()
	count := atomic.LoadUint64(&r.completed)
	if r.lastTick.IsZero() {
		r.lastTick = now
		r.lastCount = count
		return
	}
	delta := now.Sub(r.lastTick).Seconds()
	if delta <= 0 {
		return
	}
	instant := float64(count-r.lastCount) / delta
	if r.rateEMA == 0 {
		r.rateEMA = instant
	} else {
		alpha := 0.2
		r.rateEMA = alpha*instant + (1-alpha)*r.rateEMA
	}
	r.lastTick = now
	r.lastCount = count
}

func (r *Runner) refresh() {
	enqueued := atomic.LoadUint64(&r.enqueued)
	inFlight := atomic.LoadUint64(&r.inFlight)
	completed := atomic.LoadUint64(&r.completed)
	alive := atomic.LoadUint64(&r.alive)
	found := atomic.LoadUint64(&r.found)
	total := r.config.Total
	percent := 0.0
	if total > 0 {
		percent = (float64(completed) / float64(total)) * 100
	}
	queued := queuedCount(enqueued, inFlight, completed)

	r.target.Clear()
	fmt.Fprintf(r.target, "CIDR  : %s\n", r.config.CIDR)
	fmt.Fprintf(r.target, "Range : %s - %s\n", r.config.RangeStart, r.config.RangeEnd)

	r.stats.Clear()
	fmt.Fprintf(r.stats, "Alive : %-6d %s\n", alive, statBar(alive, 10))
	fmt.Fprintf(r.stats, "Ports : %-6d [Found]\n", found)

	r.progress.Clear()
	fmt.Fprintf(r.progress, "%s %.2f%%\n\n", progressBar(percent, 60), percent)
	fmt.Fprintf(r.progress, "Queued      : %-8d Rate        : %.1f hosts/s\n", queued, r.rateEMA)
	fmt.Fprintf(r.progress, "In Progress : %-8d ETA         : %s\n", inFlight, formatETA(total, completed, r.rateEMA))
	fmt.Fprintf(r.progress, "Completed   : %-8d Concurrency : %d\n", completed, r.config.Concurrency)

	r.liveMu.Lock()
	lines := make([]string, len(r.liveLines))
	copy(lines, r.liveLines)
	r.liveMu.Unlock()

	r.ports.Clear()
	for _, line := range lines {
		fmt.Fprintln(r.ports, line)
	}

	r.app.Draw()
}

func formatETA(total, completed uint64, rate float64) string {
	if total == 0 || completed >= total || rate <= 0 {
		return "--"
	}
	remaining := float64(total - completed)
	seconds := remaining / rate
	if seconds < 1 {
		return "<1s"
	}
	duration := time.Duration(seconds * float64(time.Second))
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	secs := int(duration.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, secs)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func pendingCount(total, enqueued uint64) uint64 {
	if total == 0 || enqueued >= total {
		return 0
	}
	return total - enqueued
}

func queuedCount(enqueued, inFlight, completed uint64) uint64 {
	if enqueued <= inFlight+completed {
		return 0
	}
	return enqueued - inFlight - completed
}

func (r *Runner) addLiveLine(ip, status string) {
	if ip == "" && status == "" {
		return
	}
	line := ip
	if status != "" {
		line = fmt.Sprintf("%s -> %s", ip, status)
	}
	if ip == "" {
		line = status
	}
	if ip == "Scanning..." {
		line = "Scanning..."
	}
	r.liveMu.Lock()
	r.liveLines = append([]string{line}, r.liveLines...)
	if len(r.liveLines) > 12 {
		r.liveLines = r.liveLines[:12]
	}
	r.liveMu.Unlock()
}

func formatResultLine(result models.Result) string {
	if len(result.Ports) == 0 {
		return "[UP]"
	}
	ports := make([]string, 0, len(result.Ports))
	for _, port := range result.Ports {
		ports = append(ports, fmt.Sprintf("%d", port))
	}
	return fmt.Sprintf("[UP] Found %d ports (%s)", len(result.Ports), strings.Join(ports, ", "))
}

func progressBar(percent float64, width int) string {
	if width <= 0 {
		return "[]"
	}
	filled := int((percent / 100) * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("=", filled)
	space := strings.Repeat(".", width-filled)
	return fmt.Sprintf("[%s>%s]", bar, space)
}

func statBar(value uint64, width int) string {
	if width <= 0 {
		return "[]"
	}
	filled := width
	if value == 0 {
		filled = 0
	}
	return fmt.Sprintf("[%s%s]", strings.Repeat("#", filled), strings.Repeat(" ", width-filled))
}

func headerArt() string {
	return "________        _________                        ___________              __\n" +
		" /  _____/  ____ /   _____/ ____ _____    ____    \\_   _____/____    ______/  |_ \n" +
		"/   \\  ___ /  _ \\\\_____  \\_/ ___\\__  \\  /    \\    |    __) \\__  \\  /  ___/\\   __\\\n" +
		"\\    \\_\\  (  <_> )        \\  \\___ / __ \\|   |  \\   |     \\   / __ \\_\\___ \\  |  |  \n" +
		" \\______  /\\____/_______  /\\___  >____  /___|  /   \\___  /  (____  /____  > |__|  \n" +
		"        \\/              \\/     \\/     \\/     \\/        \\/         \\/     \\/       \n"
}
