package utils

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"runtime"
	"time"
)

type PerformanceMonitor struct {
	startTime    time.Time
	startMem     runtime.MemStats
	profilerStop func()
}

func NewPerformanceMonitor() *PerformanceMonitor {
	pm := &PerformanceMonitor{
		startTime: time.Now(),
	}

	pm.profilerStop = profile.Start(
		profile.CPUProfile,
		profile.MemProfile,
		profile.ProfilePath("./performance"),
		profile.NoShutdownHook,
	).Stop

	runtime.GC()
	runtime.ReadMemStats(&pm.startMem)

	return pm
}

func (pm *PerformanceMonitor) Stop() {
	if pm == nil {
		return
	}

	if pm.profilerStop != nil {
		pm.profilerStop()
	}

	pm.printReport()
}

func (pm *PerformanceMonitor) printReport() {
	logrus.Infof("%s ", color.New(color.FgHiYellow, color.Bold).Sprint("Performance Report -------------------"))

	duration := time.Since(pm.startTime)

	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)

	memUsed := float64(endMem.Alloc-pm.startMem.Alloc) / 1024 / 1024
	numGoroutines := runtime.NumGoroutine()

	logrus.Info(color.New(color.FgRed, color.Italic).Sprint(fmt.Sprintf("Memory used:                   %.2f MB", memUsed)))
	logrus.Info(color.New(color.FgMagenta, color.Italic).Sprint(fmt.Sprintf("Goroutines:                    %d", numGoroutines)))
	logrus.Info(color.New(color.FgGreen, color.Italic).Sprint(fmt.Sprintf("Total time:                    %s", formatDuration(duration))))
}

func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.0fns", float64(d.Nanoseconds()))
	} else if d < time.Millisecond {
		return fmt.Sprintf("%.2fμs", float64(d.Nanoseconds())/1000)
	} else if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1000000)
	} else {
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
}
