package output

import (
	"os"
)

// IsStdoutTTY reports whether stdout is an interactive terminal.
func IsStdoutTTY() bool {
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
