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
	"archive/tar"
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"git.facekapow.dev/facekapow/pacrat/util"
)

type Package struct {
	Name            string
	Base            string
	Version         string
	Description     string
	URL             *url.URL
	BuildDate       time.Time
	Packager        string
	Size            uint64
	CompressedSize  uint64
	Architecture    string
	Licenses        []string
	Filenames       []string
	Groups          []string
	Depends         []string
	Replaces        []string
	Conflicts       []string
	Provides        []string
	OptionalDepends []string
	MakeDepends     []string
	CheckDepends    []string
	MD5             []byte
	SHA256          []byte
	Signature       []byte
	Compression     Compression
}

func ReadPackage(source io.Reader, compressed bool) (*Package, error) {
	result := &Package{
		Licenses:        make([]string, 0),
		Filenames:       make([]string, 0),
		Groups:          make([]string, 0),
		Depends:         make([]string, 0),
		Replaces:        make([]string, 0),
		Conflicts:       make([]string, 0),
		Provides:        make([]string, 0),
		OptionalDepends: make([]string, 0),
		MakeDepends:     make([]string, 0),
		CheckDepends:    make([]string, 0),
		Compression:     CompressionZST,
	}

	md5Sum := md5.New()
	sha256Sum := sha256.New()
	compressedSize := util.NewCountingWriter()
	tee := io.TeeReader(source, io.MultiWriter(md5Sum, sha256Sum, compressedSize))

	var tarSource io.Reader = tee

	if compressed {
		_, compressionReader, compression, err := NewDetectedCompressionReader(tee)
		if err != nil {
			return nil, err
		}
		defer compressionReader.Close()

		result.Compression = compression
		tarSource = compressionReader
	}

	tarReader := tar.NewReader(tarSource)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == ".PKGINFO" {
			// special package information file
			scanner := bufio.NewScanner(tarReader)

			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "#") {
					// ignore this line
					continue
				}

				key, value, found := strings.Cut(scanner.Text(), "=")
				if !found {
					// ignore this line?
					continue
				}

				key = strings.TrimSpace(key)
				value = strings.TrimSpace(value)

				switch key {
				case "pkgname":
					result.Name = value
				case "pkgbase":
					result.Base = value
				case "pkgver":
					result.Version = value
				case "pkgdesc":
					result.Description = value
				case "url":
					result.URL, _ = url.Parse(value)
				case "builddate":
					if builddateInt64, err := strconv.ParseInt(value, 10, 64); err == nil {
						result.BuildDate = time.Unix(builddateInt64, 0)
					}
				case "packager":
					result.Packager = value
				case "size":
					result.Size, _ = strconv.ParseUint(value, 10, 64)
				case "arch":
					result.Architecture = value
				case "license":
					result.Licenses = append(result.Licenses, value)
				case "group":
					result.Groups = append(result.Groups, value)
				case "depend":
					result.Depends = append(result.Depends, value)
				case "replaces":
					result.Replaces = append(result.Replaces, value)
				case "conflict":
					result.Conflicts = append(result.Conflicts, value)
				case "provides":
					result.Provides = append(result.Provides, value)
				case "optdepend":
					result.OptionalDepends = append(result.OptionalDepends, value)
				case "makedepend":
					result.MakeDepends = append(result.MakeDepends, value)
				case "checkdepend":
					result.CheckDepends = append(result.CheckDepends, value)
				default:
					// ignore invalid key?
				}
			}

			if err = scanner.Err(); err != nil {
				return nil, err
			}

			if result.Name == "" || result.Version == "" {
				// these are required
				return nil, fmt.Errorf("name and version not found in package info")
			}
		} else if header.Name != ".MTREE" && header.Name != ".BUILDINFO" {
			// ignore the other two special files and add the rest to the file list
			result.Filenames = append(result.Filenames, header.Name)
		}
	}

	result.MD5 = md5Sum.Sum(nil)
	result.SHA256 = sha256Sum.Sum(nil)
	result.CompressedSize = uint64(compressedSize.Count())

	return result, nil
}

func readPackageFromDesc(source io.Reader) (*Package, error) {
	result := &Package{
		Licenses:        make([]string, 0),
		Groups:          make([]string, 0),
		Depends:         make([]string, 0),
		Replaces:        make([]string, 0),
		Conflicts:       make([]string, 0),
		Provides:        make([]string, 0),
		OptionalDepends: make([]string, 0),
		MakeDepends:     make([]string, 0),
		CheckDepends:    make([]string, 0),
	}
	scanner := bufio.NewScanner(source)
	key := ""
	expectingKey := true

	for scanner.Scan() {
		line := scanner.Text()
		if expectingKey {
			if !strings.HasPrefix(line, "%") || !strings.HasSuffix(line, "%") {
				return nil, fmt.Errorf("invalid key: %s", line)
			}
			key = strings.TrimSuffix(strings.TrimPrefix(line, "%"), "%")
			expectingKey = false
		} else if len(line) == 0 {
			// empty lines denote the end of the current key
			expectingKey = true
		} else {
			switch key {
			case "FILENAME":
				// we ignore this
			case "NAME":
				result.Name = line
			case "BASE":
				result.Base = line
			case "VERSION":
				result.Version = line
			case "DESC":
				result.Description = line
			case "GROUPS":
				result.Groups = append(result.Groups, line)
			case "CSIZE":
				result.CompressedSize, _ = strconv.ParseUint(line, 10, 64)
			case "ISIZE":
				result.Size, _ = strconv.ParseUint(line, 10, 64)
			case "MD5SUM":
				if sum, err := hex.DecodeString(line); err == nil {
					result.MD5 = sum
				}
			case "SHA256SUM":
				if sum, err := hex.DecodeString(line); err == nil {
					result.SHA256 = sum
				}
			case "PGPSIG":
				if sigBytes, err := base64.StdEncoding.DecodeString(line); err == nil {
					result.Signature = sigBytes
				}
			case "URL":
				result.URL, _ = url.Parse(line)
			case "LICENSE":
				result.Licenses = append(result.Licenses, line)
			case "ARCH":
				result.Architecture = line
			case "BUILDDATE":
				if builddateInt64, err := strconv.ParseInt(line, 10, 64); err == nil {
					result.BuildDate = time.Unix(builddateInt64, 0)
				}
			case "PACKAGER":
				result.Packager = line
			case "REPLACES":
				result.Replaces = append(result.Replaces, line)
			case "CONFLICTS":
				result.Conflicts = append(result.Conflicts, line)
			case "PROVIDES":
				result.Provides = append(result.Provides, line)
			case "DEPENDS":
				result.Depends = append(result.Depends, line)
			case "OPTDEPENDS":
				result.OptionalDepends = append(result.OptionalDepends, line)
			case "MAKEDEPENDS":
				result.MakeDepends = append(result.MakeDepends, line)
			case "CHECKDEPENDS":
				result.CheckDepends = append(result.CheckDepends, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if result.Name == "" || result.Version == "" {
		// these are required
		return nil, fmt.Errorf("name and version not found in package info")
	}

	return result, nil
}

func (pkg *Package) generateDescription() string {
	contents := ""

	formatEntry := func(key string, values ...string) {
		// if every string is empty, we don't output this entry
		empty := true
		for _, val := range values {
			if val != "" {
				empty = false
				break
			}
		}
		if empty {
			return
		}

		contents += "%" + key + "%\n" + strings.Join(values, "\n") + "\n\n"
	}

	formatEntry("FILENAME", pkg.RepositoryFilename())
	formatEntry("NAME", pkg.Name)
	formatEntry("BASE", pkg.Base)
	formatEntry("VERSION", pkg.Version)
	formatEntry("DESC", pkg.Description)
	formatEntry("GROUPS", pkg.Groups...)
	formatEntry("CSIZE", strconv.FormatUint(pkg.CompressedSize, 10))
	formatEntry("ISIZE", strconv.FormatUint(pkg.Size, 10))
	if pkg.MD5 != nil {
		formatEntry("MD5SUM", hex.EncodeToString(pkg.MD5))
	}
	if pkg.SHA256 != nil {
		formatEntry("SHA256SUM", hex.EncodeToString(pkg.SHA256))
	}
	if pkg.Signature != nil {
		formatEntry("PGPSIG", base64.StdEncoding.EncodeToString(pkg.Signature))
	}
	if pkg.URL != nil {
		formatEntry("URL", pkg.URL.String())
	}
	formatEntry("LICENSE", pkg.Licenses...)
	formatEntry("ARCH", pkg.Architecture)
	formatEntry("BUILDDATE", strconv.FormatInt(pkg.BuildDate.Unix(), 10))
	formatEntry("PACKAGER", pkg.Packager)
	formatEntry("REPLACES", pkg.Replaces...)
	formatEntry("CONFLICTS", pkg.Conflicts...)
	formatEntry("PROVIDES", pkg.Provides...)
	formatEntry("DEPENDS", pkg.Depends...)
	formatEntry("OPTDEPENDS", pkg.OptionalDepends...)
	formatEntry("MAKEDEPENDS", pkg.MakeDepends...)
	formatEntry("CHECKDEPENDS", pkg.CheckDepends...)

	return contents
}

func (pkg *Package) RepositoryFilename() string {
	return pkg.Name + "-" + pkg.Version + "-" + pkg.Architecture + ".pkg.tar" + pkg.Compression.CompressionFileExtension()
}
