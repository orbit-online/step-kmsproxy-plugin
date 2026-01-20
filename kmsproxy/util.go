package kmsproxy

import (
	"fmt"
	"log/slog"

	"github.com/fsnotify/fsnotify"
)

func WatchFile(path string, onChange func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create filesystem watcher: %w", err)
	}
	defer watcher.Close()
	err = watcher.Add(path)
	if err != nil {
		return fmt.Errorf("failed to watch path %s: %w", path, err)
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			onChange()
			slog.Debug("File changed", "path", event.Name)
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			slog.Warn("Error while watching for file changes", "err", err)
		}
	}
}
