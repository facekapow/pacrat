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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/facekapow/pacrat/util"
)

type Database struct {
	Packages []*Package
}

type descEntry struct {
	contents string
	header   *tar.Header
}

func ReadDatabase(mainDBSource io.Reader, fileDBSource io.Reader) (*Database, error) {
	result := &Database{
		Packages: make([]*Package, 0),
	}

	_, compressionReader, _, err := NewDetectedCompressionReader(fileDBSource)
	if err != nil {
		return nil, err
	}
	defer compressionReader.Close()

	tarReader := tar.NewReader(compressionReader)

	files := make(map[string][]string)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Typeflag == tar.TypeDir {
			// ignore directories themselves
			// TODO: maybe verify the directory name?
			continue
		}

		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("invalid file database: found non-regular file")
		}

		if strings.HasSuffix(header.Name, "/desc") {
			// ignore this; we'll use the entry from the main database
			continue
		}

		name, found := strings.CutSuffix(header.Name, "/files")
		if !found {
			return nil, fmt.Errorf("invalid file database: found file that wasn't a package file list file")
		}

		if strings.ContainsRune(name, '/') {
			return nil, fmt.Errorf("invalid file database: found file in nested directory")
		}

		rawFiles, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, err
		}

		fileList := strings.Split(string(rawFiles), "\n")
		if len(fileList) < 1 {
			return nil, fmt.Errorf("invalid package file list file: empty file")
		}

		files[name] = fileList[1:]
	}

	_, compressionReader, _, err = NewDetectedCompressionReader(mainDBSource)
	if err != nil {
		return nil, err
	}
	defer compressionReader.Close()

	tarReader = tar.NewReader(compressionReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Typeflag == tar.TypeDir {
			// ignore directories themselves
			// TODO: maybe verify the directory name?
			continue
		}

		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("invalid main database: found non-regular file")
		}

		name, found := strings.CutSuffix(header.Name, "/desc")
		if !found {
			return nil, fmt.Errorf("invalid main database: found file that wasn't a package description file")
		}

		if strings.ContainsRune(name, '/') {
			return nil, fmt.Errorf("invalid main database: found file in nested directory")
		}

		pkg, err := readPackageFromDesc(tarReader)
		if err != nil {
			return nil, err
		}

		if pkgfiles, ok := files[name]; ok {
			pkg.Filenames = pkgfiles
		} else {
			pkg.Filenames = make([]string, 0)
		}

		result.Packages = append(result.Packages, pkg)
	}

	return result, nil
}

func (db *Database) Write(mainDBDest io.Writer, fileDBDest io.Writer, compression Compression) error {
	descs := make(map[string]descEntry)

	compressionWriter, err := NewCompressionWriter(compression, mainDBDest)
	if err != nil {
		return err
	}
	defer compressionWriter.Close()

	tarWriter := tar.NewWriter(compressionWriter)
	defer tarWriter.Close()

	for _, pkg := range db.Packages {
		contents := pkg.generateDescription()
		entry := descEntry{
			contents: contents,
			header: &tar.Header{
				Typeflag: tar.TypeReg,
				Name:     pkg.Name + "-" + pkg.Version + "/desc",
				Size:     int64(len(contents)),
				Mode:     0644,
				Uid:      0,
				Gid:      0,
				Uname:    "root",
				Gname:    "root",
				ModTime:  time.Now(),
			},
		}
		descs[pkg.Name+"-"+pkg.Version] = entry

		err := tarWriter.WriteHeader(entry.header)
		if err != nil {
			return err
		}

		_, err = io.WriteString(tarWriter, entry.contents)
		if err != nil {
			return err
		}
	}

	compressionWriter, err = NewCompressionWriter(compression, fileDBDest)
	if err != nil {
		return err
	}
	defer compressionWriter.Close()

	tarWriter = tar.NewWriter(compressionWriter)
	defer tarWriter.Close()

	for _, pkg := range db.Packages {
		contents := "%FILES%\n" + strings.Join(pkg.Filenames, "\n")
		if !strings.HasSuffix(contents, "\n") {
			contents += "\n"
		}

		err := tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     pkg.Name + "-" + pkg.Version + "/files",
			Size:     int64(len(contents)),
			Mode:     0644,
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			ModTime:  time.Now(),
		})
		if err != nil {
			return err
		}

		_, err = io.WriteString(tarWriter, contents)
		if err != nil {
			return err
		}

		entry := descs[pkg.Name+"-"+pkg.Version]

		err = tarWriter.WriteHeader(entry.header)
		if err != nil {
			return err
		}

		_, err = io.WriteString(tarWriter, entry.contents)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *Database) Add(pkg *Package, replaceIfExists bool) error {
	for i, dbPkg := range db.Packages {
		if dbPkg.Name != pkg.Name || dbPkg.Version != pkg.Version {
			continue
		}

		// if we got here, this entry has the same name and version as the new package
		if !replaceIfExists {
			return os.ErrExist
		}

		// if we got here, we're going to replace the package
		db.Packages[i] = pkg
		return nil
	}

	// if we got here, the new package is completely new (i.e. does not share a name and version with an existing package)
	db.Packages = append(db.Packages, pkg)
	return nil
}

func (db *Database) Find(name string, version string) (*Package, error) {
	for _, dbPkg := range db.Packages {
		if dbPkg.Name != name || dbPkg.Version != version {
			continue
		}

		return dbPkg, nil
	}

	return nil, os.ErrNotExist
}

func (db *Database) FindAll(name string) []*Package {
	result := make([]*Package, 0)

	for _, dbPkg := range db.Packages {
		if dbPkg.Name != name {
			continue
		}

		result = append(result, dbPkg)
	}

	return result
}

func (db *Database) Remove(name string, version string) error {
	for i, dbPkg := range db.Packages {
		if dbPkg.Name != name || dbPkg.Version != version {
			continue
		}

		util.RemoveSliceElement(&db.Packages, i)
		return nil
	}

	return os.ErrNotExist
}

func (db *Database) RemoveAll(name string) {
	pkgs := db.FindAll(name)

	for _, pkg := range pkgs {
		db.Remove(pkg.Name, pkg.Version)
	}
}
