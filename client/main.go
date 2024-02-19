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
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
)

var globalConfig Config = Config{}

func main() {
	flag.StringVar(&globalConfig.General.ServerURL, "server", "", "The URL of the Pacrat server")

	uploadPGPKey := &uploadPGPKeyCommand{}
	uploadPackage := &uploadPackageCommand{}

	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(uploadPGPKey, "")
	subcommands.Register(uploadPackage, "")
	subcommands.Register(subcommands.Alias("upload", uploadPackage), "")

	flag.Parse()

	os.Exit(int(subcommands.Execute(context.Background())))
}
