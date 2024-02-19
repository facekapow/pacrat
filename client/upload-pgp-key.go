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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"git.facekapow.dev/facekapow/pacrat/util"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/google/subcommands"
)

type uploadPGPKeyCommand struct {
}

func (cmd *uploadPGPKeyCommand) Name() string {
	return "upload-pgp-key"
}

func (cmd *uploadPGPKeyCommand) Synopsis() string {
	return "Upload a PGP private signing key to the server"
}

func (cmd *uploadPGPKeyCommand) Usage() string {
	return `upload-PGP-key <key-path>
`
}

func (cmd *uploadPGPKeyCommand) SetFlags(flagSet *flag.FlagSet) {
	// none
}

func (cmd *uploadPGPKeyCommand) Execute(_ context.Context, flagSet *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if len(flagSet.Args()) != 1 {
		flagSet.Usage()
		return subcommands.ExitUsageError
	}

	keyFile, err := os.Open(flagSet.Arg(0))
	if err != nil {
		fmt.Println("Failed to open key file:", err)
		return subcommands.ExitFailure
	}
	defer keyFile.Close()

	key, err := crypto.NewKeyFromReader(keyFile)
	if err != nil {
		fmt.Println("Failed to parse key file:", err)
		return subcommands.ExitFailure
	}
	defer key.ClearPrivateParams()

	timepoint := time.Now().Unix()

	if !key.IsPrivate() {
		fmt.Println("Invalid key: not a private key")
		return subcommands.ExitFailure
	}

	if key.IsExpired(timepoint) {
		fmt.Println("Invalid key: expired")
		return subcommands.ExitFailure
	}

	if !key.CanVerify(timepoint) {
		fmt.Println("Invalid key: not a signing key")
		return subcommands.ExitFailure
	}

	client, clientInfo, err := getServerClient(globalConfig.General.ServerURL)
	if err != nil {
		fmt.Println("Failed to obtain a connection to the server:", err)
		return subcommands.ExitFailure
	}
	// we don't actually care if it fails to store, so we can ignore errors in here
	defer saveClientToken(client, clientInfo)

	keyBytes, err := key.Serialize()
	if err != nil {
		fmt.Println("Failed to serialize key for transmission:", err)
		return subcommands.ExitFailure
	}
	defer util.ClearSlice(keyBytes)

	res, err := client.Post(globalConfig.General.ServerURL+"/upload_pgp_key", "application/octet-stream", bytes.NewReader(keyBytes))
	if err != nil {
		fmt.Println("Failed to perform server request (with upload):", err)
		return subcommands.ExitFailure
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Failed to read response body:", err)
		return subcommands.ExitFailure
	}

	if res.StatusCode != http.StatusOK {
		errorData := errorResponse{}
		_ = json.Unmarshal(responseBody, &errorData)
		fmt.Println("Request returned failure status:", res.StatusCode, errorData.Message)
		return subcommands.ExitFailure
	}

	data := uploadPGPKeyResponse{}
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		fmt.Println("Failed to parse response body (", err, "). However, server claims success (response code = 200 OK)")
		return subcommands.ExitFailure
	}

	fmt.Println("PGP key uploaded successfully (primary fingerprint = ", data.PrimaryFingerprint, ", subkey fingerprints = ", data.SubkeyFingerprints, ")")

	return subcommands.ExitSuccess
}
