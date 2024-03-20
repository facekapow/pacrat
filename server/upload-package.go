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

package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"syscall"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/facekapow/pacrat/alp"
	"github.com/facekapow/pacrat/common"
	"github.com/gin-gonic/gin"
)

const dbFileMode = 0640

type safeReplaceCleanupContext struct {
	needsCleanup bool
	existed      bool
	dest         string
}

func cleanupTempFile(ptrTmpFile **os.File) {
	tmpFile := *ptrTmpFile
	if tmpFile != nil {
		os.Remove(tmpFile.Name())
	}
	if tmpFile != nil {
		tmpFile.Close()
	}
}

func closeIfNotNilCrypto(ptrCloser *crypto.WriteCloser) {
	closer := *ptrCloser
	if closer != nil {
		closer.Close()
	}
}

func safeReplaceFile(source string, dest string) (safeReplaceCleanupContext, error) {
	result := safeReplaceCleanupContext{
		needsCleanup: false,
		existed:      true,
		dest:         dest,
	}
	if err := os.Rename(dest, dest+".old"); err != nil {
		if !errors.Is(err, syscall.ENOENT) {
			return result, err
		}
		result.existed = false
	} else {
		result.needsCleanup = true
	}
	if err := os.Rename(source, dest); err != nil {
		return result, err
	}
	result.needsCleanup = true
	return result, nil
}

func safeReplaceCleanup(ptrAllOK *bool, context safeReplaceCleanupContext) error {
	if !context.needsCleanup {
		return nil
	}
	if *ptrAllOK {
		if context.existed {
			return os.Remove(context.dest + ".old")
		}
	} else {
		if context.existed {
			return os.Rename(context.dest+".old", context.dest)
		} else {
			return os.Remove(context.dest)
		}
	}
	return nil
}

// This request handler must have ensureAdminMiddleware and ensurePackageDBMiddleware installed before it
func uploadPackage(ctx *gin.Context) {
	logger := ctx.MustGet(LOGGER_KEY).(*slog.Logger)
	db := getContextPackageDB(ctx)
	config := getContextConfig(ctx)
	pgp := getContextPGPContext(ctx)

	rawKey, exists := ctx.Get(PGP_KEY_KEY)
	if !exists {
		ctx.JSON(http.StatusFailedDependency, gin.H{
			"message": "Missing PGP key for user",
			"code":    common.ErrCodeMissingPGPKey,
		})
		return
	}

	key := rawKey.(*crypto.Key)
	defer key.ClearPrivateParams()

	file, err := ctx.FormFile("package")
	if err != nil {
		ctx.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid file upload form",
			"code":    common.ErrCodeInvalidFileUploadForm,
		})
		return
	}

	tmpFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-package-upload-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpFile)

	if err = os.Chmod(tmpFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	src, err := file.Open()
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer src.Close()

	written, err := io.Copy(tmpFile, src)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	logger.Debug("saved package to temporary file",
		"size", written,
		"path", tmpFile.Name(),
	)

	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	pkg, err := alp.ReadPackage(tmpFile, true)
	if err != nil {
		ctx.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to read package information",
			"code":    common.ErrCodeInvalidPackage,
		})
		return
	}

	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	tmpMainDBFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-update-main-db-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpMainDBFile)

	if err = os.Chmod(tmpMainDBFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	tmpFileDBFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-update-file-db-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpFileDBFile)

	if err = os.Chmod(tmpFileDBFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	signer, err := pgp.Sign().
		SigningKey(key).
		Detached().
		SignTime(time.Now().Unix()).
		New()
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	tmpMainDBSigFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-update-main-db-sig-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpMainDBSigFile)

	if err = os.Chmod(tmpMainDBSigFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	tmpFileDBSigFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-update-file-db-sig-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpFileDBSigFile)

	if err = os.Chmod(tmpFileDBSigFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	tmpPkgSigFile, err := os.CreateTemp(config.DB.TemporaryDirectory, "pacrat-package-sig-")
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer cleanupTempFile(&tmpPkgSigFile)

	if err = os.Chmod(tmpPkgSigFile.Name(), dbFileMode); err != nil {
		internalServerError(ctx, err)
		return
	}

	mainDBSigWriter, err := signer.SigningWriter(tmpMainDBSigFile, crypto.Bytes)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer closeIfNotNilCrypto(&mainDBSigWriter)

	fileDBSigWriter, err := signer.SigningWriter(tmpFileDBSigFile, crypto.Bytes)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer closeIfNotNilCrypto(&fileDBSigWriter)

	sigBuffer := &bytes.Buffer{}
	pkgSigWriter, err := signer.SigningWriter(io.MultiWriter(tmpPkgSigFile, sigBuffer), crypto.Bytes)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer closeIfNotNilCrypto(&pkgSigWriter)

	_, err = io.Copy(pkgSigWriter, tmpFile)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	pkgSigWriter.Close()
	pkgSigWriter = nil

	pkg.Signature = sigBuffer.Bytes()

	db.mutex.Lock()
	defer db.mutex.Unlock()

	allOK := false

	prevPkgs := db.database.FindAll(pkg.Name)
	for _, prevPkg := range prevPkgs {
		_ = db.database.Remove(prevPkg.Name, prevPkg.Version)
	}
	defer func() {
		if allOK {
			return
		}

		for _, prevPkg := range prevPkgs {
			_ = db.database.Add(prevPkg, true)
		}
	}()

	if err = db.database.Add(pkg, true); err != nil {
		if err == os.ErrExist {
			ctx.JSON(http.StatusConflict, gin.H{
				"message": "Package already exists",
				"code":    common.ErrCodePackageAlreadyExists,
			})
		} else {
			internalServerError(ctx, err)
		}
		return
	}
	defer func() {
		if allOK {
			return
		}

		db.database.Remove(pkg.Name, pkg.Version)
	}()

	// the above deferred function will always remove the newly added package (even if it was previously in the database) upon failure.
	// however, this is fine because the previous deferred function (which will always run after it) restores all the packages previously
	// in the database.

	err = db.database.Write(io.MultiWriter(tmpMainDBFile, mainDBSigWriter), io.MultiWriter(tmpFileDBFile, fileDBSigWriter), config.DB.Compression)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	mainDBSigWriter.Close()
	mainDBSigWriter = nil

	fileDBSigWriter.Close()
	fileDBSigWriter = nil

	// now let's try to move the files into place
	//
	// at each step, we save the old file (if it exists) in case the operation fails, so we can revert everything

	dstPkgPath := path.Join(config.DB.PackageStorePath(), pkg.Name+"-"+pkg.Version+"-"+pkg.Architecture+".pkg.tar"+pkg.Compression.CompressionFileExtension())

	// first, the package itself
	pkgCleanup, err := safeReplaceFile(tmpFile.Name(), dstPkgPath)
	defer safeReplaceCleanup(&allOK, pkgCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpFile.Close()
	tmpFile = nil

	// now let's rename the package's signature
	pkgSigCleanup, err := safeReplaceFile(tmpPkgSigFile.Name(), dstPkgPath+".sig")
	defer safeReplaceCleanup(&allOK, pkgSigCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpPkgSigFile.Close()
	tmpPkgSigFile = nil

	// now let's do the databases

	// start off with the less important one (the file DB)
	fileDBCleanup, err := safeReplaceFile(tmpFileDBFile.Name(), config.DB.FileDBPath())
	defer safeReplaceCleanup(&allOK, fileDBCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpFileDBFile.Close()
	tmpFileDBFile = nil

	// and its signature
	fileDBSigCleanup, err := safeReplaceFile(tmpFileDBSigFile.Name(), config.DB.FileDBPath()+".sig")
	defer safeReplaceCleanup(&allOK, fileDBSigCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpFileDBSigFile.Close()
	tmpFileDBSigFile = nil

	// now the more important DB (the main DB)
	mainDBCleanup, err := safeReplaceFile(tmpMainDBFile.Name(), config.DB.MainDBPath())
	defer safeReplaceCleanup(&allOK, mainDBCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpMainDBFile.Close()
	tmpMainDBFile = nil

	// and its signature
	mainDBSigCleanup, err := safeReplaceFile(tmpMainDBSigFile.Name(), config.DB.MainDBPath()+".sig")
	defer safeReplaceCleanup(&allOK, mainDBSigCleanup)
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	tmpMainDBSigFile.Close()
	tmpMainDBSigFile = nil

	// alright, everything's finally all good here!
	allOK = true

	// try to remove the files for the old versions (if any) but don't worry if any of them fail
	for _, prevPkg := range prevPkgs {
		_ = os.Remove(prevPkg.RepositoryFilename())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"name":    pkg.Name,
		"version": pkg.Version,
	})
}
