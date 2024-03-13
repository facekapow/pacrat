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

package alp

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/dsnet/compress/bzip2"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

var ErrUnknownCompression = errors.New("unknown compression format")

const (
	CompressionGZ Compression = iota
	CompressionBZ
	CompressionXZ
	CompressionZST
)

var MagicGZ = [...]byte{0x1f, 0x8b}
var MagicBZ = [...]byte{0x42, 0x5a, 0x68}
var MagicXZ = [...]byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}
var MagicZST = [...]byte{0x28, 0xb5, 0x2f, 0xfd}

type Compression int

func (cmp *Compression) MarshalText() ([]byte, error) {
	switch *cmp {
	case CompressionGZ:
		return []byte("gz"), nil
	case CompressionBZ:
		return []byte("bz"), nil
	case CompressionXZ:
		return []byte("xz"), nil
	case CompressionZST:
		return []byte("zst"), nil
	default:
		return nil, fmt.Errorf("unknown compression value %d", *cmp)
	}
}

func (cmp *Compression) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "gz", "gzip", ".gz":
		*cmp = CompressionGZ
		return nil
	case "bz", "bzip", "bz2", "bzip2", ".bz", ".bz2":
		*cmp = CompressionBZ
		return nil
	case "xz", ".xz":
		*cmp = CompressionXZ
		return nil
	case "zst", "zstd", ".zst":
		*cmp = CompressionZST
		return nil
	default:
		return fmt.Errorf("unknown compression format: %s", string(text))
	}
}

func (cmp *Compression) CompressionFileExtension() string {
	switch *cmp {
	case CompressionGZ:
		return ".gz"
	case CompressionBZ:
		return ".bz"
	case CompressionXZ:
		return ".xz"
	case CompressionZST:
		return ".zst"
	default:
		// just default to GZ for now
		return ".gz"
	}
}

func DetectCompressionFormat(source io.Reader) (io.Reader, Compression, error) {
	defaultCompression := CompressionGZ

	bufReader := bufio.NewReader(source)
	// we now need to ensure we return the buffered reader so that the bytes we peek aren't lost
	source = bufReader

	// first, try GZ since it only requires 2 bytes
	buf, err := bufReader.Peek(len(MagicGZ))
	if err != nil {
		return source, defaultCompression, err
	}
	if slices.Equal(buf, MagicGZ[:]) {
		return source, CompressionGZ, nil
	}

	// now, try BZ since it requires 3 bytes
	buf, err = bufReader.Peek(len(MagicBZ))
	if err != nil {
		return source, defaultCompression, err
	}
	if slices.Equal(buf, MagicBZ[:]) {
		return source, CompressionBZ, err
	}

	// next, try ZST since it requires 4 bytes
	buf, err = bufReader.Peek(len(MagicZST))
	if err != nil {
		return source, defaultCompression, err
	}
	if slices.Equal(buf, MagicZST[:]) {
		return source, CompressionZST, err
	}

	// finally, try XZ since it requires 6 bytes
	buf, err = bufReader.Peek(len(MagicXZ))
	if err != nil {
		return source, defaultCompression, err
	}
	if slices.Equal(buf, MagicXZ[:]) {
		return source, CompressionXZ, err
	}

	return source, CompressionGZ, ErrUnknownCompression
}

func NewDetectedCompressionReader(source io.Reader) (io.Reader, io.ReadCloser, Compression, error) {
	source, compression, err := DetectCompressionFormat(source)
	if err != nil {
		return source, nil, CompressionGZ, err
	}

	switch compression {
	case CompressionGZ:
		gzipReader, err := gzip.NewReader(source)
		if err != nil {
			return nil, nil, compression, err
		}
		return nil, gzipReader, compression, nil

	case CompressionBZ:
		bzipReader, err := bzip2.NewReader(source, nil)
		if err != nil {
			return nil, nil, compression, err
		}
		return nil, bzipReader, compression, nil

	case CompressionXZ:
		xzReader, err := xz.NewReader(source)
		if err != nil {
			return nil, nil, compression, err
		}
		return nil, io.NopCloser(xzReader), compression, nil

	case CompressionZST:
		zstReader, err := zstd.NewReader(source)
		if err != nil {
			return nil, nil, compression, err
		}
		return nil, zstReader.IOReadCloser(), compression, nil

	default:
		return source, nil, compression, ErrUnknownCompression
	}
}

func NewCompressionWriter(compression Compression, dest io.Writer) (io.WriteCloser, error) {
	switch compression {
	case CompressionGZ:
		return gzip.NewWriter(dest), nil

	case CompressionBZ:
		return bzip2.NewWriter(dest, nil)

	case CompressionXZ:
		return xz.NewWriter(dest)

	case CompressionZST:
		return zstd.NewWriter(dest)

	default:
		return nil, ErrUnknownCompression
	}
}
