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

type errorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type uploadPackageResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type uploadPGPKeyResponse struct {
	PrimaryFingerprint string   `json:"primary_fingerprint"`
	SubkeyFingerprints []string `json:"subkey_fingerprints"`
}
