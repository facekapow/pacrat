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
	"net/http"

	"github.com/facekapow/pacrat/common"
	"github.com/gin-gonic/gin"
)

func internalServerError(ctx *gin.Context, err error) {
	ctx.Error(err)
	ctx.JSON(http.StatusInternalServerError, gin.H{
		"message": "Internal server error",
		"code":    common.ErrCodeInternalServerError,
	})
}
