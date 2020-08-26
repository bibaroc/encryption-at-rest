package env

import (
	"os"
	"strconv"
)

// String returns either the env value for s0, or if not found s1.
func String(s0, s1 string) string {
	value, ok := os.LookupEnv(s0)
	if !ok {
		return s1
	}
	return value
}

// Int returns either the env value for s0, or if not found i1.
// If the value pointed by s0 cannot be used as an int, this procedure fails silently.
func Int(s0 string, i1 int) int {
	value, ok := os.LookupEnv(s0)
	if !ok {
		return i1
	}
	i2, err := strconv.Atoi(value)
	if err != nil {
		return i1
	}

	return i2
}
