package util

import "os"

func ClearSlice[T any](slice []T) {
	var empty T
	for i := range slice {
		slice[i] = empty
	}
}

func FileExists(pathString string) bool {
	stats, err := os.Stat(pathString)
	if err != nil {
		return false
	}

	return stats.Mode().IsRegular()
}

func TryFileExists(paths ...string) string {
	for _, path := range paths {
		if FileExists(path) {
			return path
		}
	}
	return ""
}
