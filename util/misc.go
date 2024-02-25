/*
 * Pacrat
 * Copyright (C) 2024 Ariel Abreu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import "os"

func ClearSlice[T any](slice []T) {
	var empty T
	for i := range slice {
		slice[i] = empty
	}
}

func RemoveSliceElement[T any](slice *[]T, index int) {
	var empty T
	orig := *slice
	orig[len(orig)-1], orig[index] = empty, orig[len(orig)-1]
	*slice = orig[:len(orig)-1]
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
