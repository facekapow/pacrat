package main

import (
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"time"

	"git.facekapow.dev/facekapow/pacrat/common"
	"git.facekapow.dev/facekapow/pacrat/util"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
