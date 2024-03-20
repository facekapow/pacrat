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
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"

	"github.com/facekapow/pacrat/common"
	"github.com/google/subcommands"
	"golang.org/x/term"
)

type uploadPackageCommand struct {
	passphrase string
}

func (cmd *uploadPackageCommand) Name() string {
	return "upload-package"
}

func (cmd *uploadPackageCommand) Synopsis() string {
	return "Upload one or more packages to the server"
}

func (cmd *uploadPackageCommand) Usage() string {
	return `upload-package [-p passphrase] <package>...
	<package>     The path to a package to upload
`
}

func (cmd *uploadPackageCommand) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&cmd.passphrase, "p", "", "The PGP key passphrase for the user the upload is being performed by")
	flagSet.StringVar(&cmd.passphrase, "passphrase", "", "The PGP key passphrase for the user the upload is being performed by")
}

func (cmd *uploadPackageCommand) Execute(_ context.Context, flagSet *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if len(flagSet.Args()) == 0 {
		fmt.Println("Missing package(s) to upload")
		return subcommands.ExitFailure
	}

	if len(flagSet.Args()) != 1 {
		fmt.Println("TODO: support uploading multiple packages at once")
		return subcommands.ExitFailure
	}

	if globalConfig.General.ServerURL == "" {
		fmt.Println("Missing server to connect to")
		return subcommands.ExitFailure
	}

	filePath := flagSet.Arg(0)

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Failed to open file:", err)
		return subcommands.ExitFailure
	}
	defer file.Close()

	client, clientInfo, err := getServerClient(globalConfig.General.ServerURL)
	if err != nil {
		fmt.Println("Failed to obtain a connection to the server:", err)
		return subcommands.ExitFailure
	}
	// we don't actually care if it fails to store, so we can ignore errors in here
	defer saveClientToken(client, clientInfo)

try_again:
	// NOTE: there's no need to `defer Close()` here because that's only necessary once we successfully pass the
	//       reader to the request
	bodyReader, bodyWriter := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, globalConfig.General.ServerURL+"/upload_package", bodyReader)
	if err != nil {
		fmt.Println("Failed to create server request:", err)
		return subcommands.ExitFailure
	}

	formWriter := multipart.NewWriter(bodyWriter)
	req.Header.Add("Content-Type", formWriter.FormDataContentType())

	errorChannel := make(chan error)

	go func() {
		defer close(errorChannel)
		defer bodyWriter.Close()
		defer formWriter.Close()

		if cmd.passphrase != "" {
			if err = formWriter.WriteField("pgp_key_passphrase", cmd.passphrase); err != nil {
				errorChannel <- err
				return
			}
		}

		fileWriter, err := formWriter.CreateFormFile("package", path.Base(filePath))
		if err != nil {
			errorChannel <- err
			return
		}

		_, err = io.Copy(fileWriter, file)
		if err != nil {
			errorChannel <- err
			return
		}
	}()

	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
	}
	err2 := <-errorChannel
	if err != nil || (err2 != nil && err2 != io.ErrClosedPipe) {
		fmt.Println("Failed to perform server request (with upload):", err, err2)
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
		if errorData.Code == common.ErrCodeMissingPGPKeyPassphrase && cmd.passphrase == "" {
			if _, err = file.Seek(0, 0); err == nil {
				if term.IsTerminal(int(os.Stdin.Fd())) {
					fmt.Fprint(os.Stderr, "PGP key passphrase (for key stored on server): ")
					rawPassphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Fprintln(os.Stderr)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Failed to read passphrase")
						return subcommands.ExitFailure
					}
					cmd.passphrase = string(rawPassphrase)
					goto try_again
				} else {
					fmt.Fprintln(os.Stderr, "PGP key passphrase (for key stored on server): ")
					scanner := bufio.NewScanner(os.Stdin)
					if !scanner.Scan() {
						fmt.Fprintln(os.Stderr)
						fmt.Fprintln(os.Stderr, "Failed to read passphrase")
						return subcommands.ExitFailure
					}
					fmt.Fprintln(os.Stderr)
					cmd.passphrase = scanner.Text()
					goto try_again
				}
			}
		}
		fmt.Println("Request returned failure status:", res.StatusCode, errorData.Message)
		return subcommands.ExitFailure
	}

	data := uploadPackageResponse{}
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		fmt.Println("Failed to parse response body (", err, "). However, server claims success (response code = 200 OK)")
		return subcommands.ExitFailure
	}

	fmt.Println("Package uploaded successfully (name = ", data.Name, ", version = ", data.Version, ")")

	return subcommands.ExitSuccess
}
