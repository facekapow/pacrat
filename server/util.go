package main

import (
	"net/http"

	"git.facekapow.dev/facekapow/pacrat/common"
	"github.com/gin-gonic/gin"
)

func internalServerError(ctx *gin.Context, err error) {
	ctx.Error(err)
	ctx.JSON(http.StatusInternalServerError, gin.H{
		"message": "Internal server error",
		"code":    common.ErrCodeInternalServerError,
	})
}
