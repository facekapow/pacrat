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
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/facekapow/pacrat/common"
	"github.com/facekapow/pacrat/util"
	"github.com/gin-gonic/gin"
)

func uploadPGPKey(ctx *gin.Context) {
	config := getContextConfig(ctx)
	userClaims := getContextUserClaims(ctx)

	key, err := crypto.NewKeyFromReader(ctx.Request.Body)
	if err != nil {
		ctx.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid PGP key",
			"code":    common.ErrCodeInvalidPGPKey,
		})
		return
	}
	defer key.ClearPrivateParams()

	if !key.IsPrivate() {
		ctx.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "Not a private PGP key",
			"code":    common.ErrCodeNotPrivatePGPKey,
		})
		return
	}

	if !key.CanVerify(time.Now().Unix()) {
		ctx.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "Not a PGP signing key",
			"code":    common.ErrCodeNotSigningPGPKey,
		})
		return
	}

	outFile, err := os.OpenFile(path.Join(config.Keystore.Path, userClaims.Username+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	keyBytes, err := key.Serialize()
	if err != nil {
		internalServerError(ctx, err)
		return
	}
	defer util.ClearSlice(keyBytes)

	_, err = outFile.Write(keyBytes)
	if err != nil {
		internalServerError(ctx, err)
		return
	}

	subkeyFingerprints := []string{}

	for _, subkey := range key.GetEntity().Subkeys {
		subkeyFingerprints = append(subkeyFingerprints, hex.EncodeToString(subkey.PrivateKey.Fingerprint))
	}

	ctx.JSON(http.StatusOK, gin.H{
		"primary_fingerprint": key.GetFingerprint(),
		"subkey_fingerprints": subkeyFingerprints,
	})
}
