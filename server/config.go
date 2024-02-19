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
	"log/slog"
	"path"

	"git.facekapow.dev/facekapow/pacrat/alp"
)

type ConfigOidc struct {
	Endpoint string `toml:"endpoint" json:"endpoint"`
	ClientID string `toml:"client_id" json:"client_id"`
}

type ConfigServer struct {
	BaseURL        string   `toml:"base_url" json:"base_url"`
	Port           int      `toml:"port" json:"port"`
	TrustedProxies []string `toml:"trusted_proxies" json:"trusted_proxies"`
}

type ConfigDB struct {
	Name               string          `toml:"name" json:"name"`
	Compression        alp.Compression `toml:"compression" json:"compression"`
	Path               string          `toml:"path" json:"path"`
	TemporaryDirectory string          `toml:"tmp_path" json:"tmp_path"`
}

func (cfg *ConfigDB) MainDBPath() string {
	return path.Join(cfg.Path, cfg.Name+".files.tar"+cfg.Compression.CompressionFileExtension())
}

func (cfg *ConfigDB) FileDBPath() string {
	return path.Join(cfg.Path, cfg.Name+".db.tar"+cfg.Compression.CompressionFileExtension())
}

func (cfg *ConfigDB) PackageStorePath() string {
	return cfg.Path
}

type ConfigKey struct {
	Passphrase string `toml:"passphrase" json:"passphrase"`
}

type ConfigKeystore struct {
	Path string `toml:"path" json:"path"`
}

type ConfigLog struct {
	Path  string     `toml:"path" json:"path"`
	Level slog.Level `toml:"level" json:"level"`
}

type Config struct {
	Oidc     ConfigOidc           `toml:"oidc" json:"oidc"`
	Server   ConfigServer         `toml:"server" json:"server"`
	DB       ConfigDB             `toml:"db" json:"db"`
	Keys     map[string]ConfigKey `toml:"keys" json:"keys"`
	Keystore ConfigKeystore       `toml:"keystore" json:"keystore"`
	Log      ConfigLog            `toml:"log" json:"log"`
}

func DefaultConfig() Config {
	return Config{
		Server: ConfigServer{
			BaseURL: "/",
			Port:    8080,
		},
		DB: ConfigDB{
			Compression:        alp.CompressionGZ,
			Path:               "db",
			TemporaryDirectory: "tmp",
		},
		Keystore: ConfigKeystore{
			Path: "pgp",
		},
		Log: ConfigLog{
			Path:  "pacrat.log.json",
			Level: slog.LevelInfo,
		},
	}
}
