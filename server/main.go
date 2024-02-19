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
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.facekapow.dev/facekapow/pacrat/alp"
	"git.facekapow.dev/facekapow/pacrat/common"
	"git.facekapow.dev/facekapow/pacrat/util"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/oauth2"
)

const (
	CONFIG_ENV_VAR    string = "PACRAT_CONFIG_PATH"
	LOG_LEVEL_ENV_VAR string = "PACRAT_LOG_LEVEL"
	WELLKNOWN_PATH    string = "/.well-known/openid-configuration"
	BEGIN_PGP         string = "-----BEGIN PGP"

	USER_INFO_CLAIMS_KEY string = "pacrat_user_info_claims"
	LOGGER_KEY           string = "pacrat_logger"
	REQUEST_ID_KEY       string = "pacrat_request_id"
	PACKAGE_DB_KEY       string = "pacrat_package_db"
	CONFIG_KEY           string = "pacrat_config"
	PGP_KEY_KEY          string = "pacrat_pgp_key"
	PGP_CONTEXT_KEY      string = "pacrat_pgp_context"
)

type CheckTokenRequest struct {
	Token string `json:"token"`
}

type UserInfoClaims struct {
	Username    string `json:"preferred_username"`
	AccessLevel string `json:"pacrat_access"`
}

type packageDB struct {
	database *alp.Database
	mutex    sync.Mutex
}

// this middleware requires loggerMiddleware to be installed before it
func authMiddleware(provider *oidc.Provider, verifier *oidc.IDTokenVerifier) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		logger := ctx.MustGet(LOGGER_KEY).(*slog.Logger)

		rawAuth := ctx.GetHeader("Authorization")
		if !strings.HasPrefix(rawAuth, "Bearer ") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Missing access token",
				"code":    common.ErrCodeMissingAccessToken,
			})
			return
		}

		token := strings.TrimPrefix(rawAuth, "Bearer ")

		if token == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Empty access token",
				"code":    common.ErrCodeEmptyAccessToken,
			})
			return
		}

		userClaims := UserInfoClaims{}

		// first, see if we can verify the access token as a valid JWT
		// (many common OIDC providers return JWT access tokens instead of opaque ones)
		jwt, err := verifier.Verify(ctx, token)
		if err == nil {
			logger.Info("authorized request using JWT access token validation")
			jwt.Claims(&userClaims)
		} else {
			// otherwise, let's try querying the OIDC provider's UserInfo endpoint
			userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}))

			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Invalid token",
					"code":    common.ErrCodeInvalidToken,
				})
				return
			}

			logger.Info("authorized request using OIDC provider UserInfo endpoint")
			userInfo.Claims(&userClaims)
		}

		if userClaims.Username == "" {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "Invalid username (empty string)",
				"code":    common.ErrCodeInvalidUsername,
			})
			return
		}

		if userClaims.AccessLevel != "user" && userClaims.AccessLevel != "admin" {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message":      "Insufficient access level",
				"code":         common.ErrCodeInsufficientAccessLevel,
				"access_level": userClaims.AccessLevel,
			})
			return
		}

		ctx.Set(USER_INFO_CLAIMS_KEY, userClaims)
	}
}

// this essentially performs the same function as Gin's logger middleware, except
// that it outputs structured logs instead of just printing a string
//
// this middleware requires requestIDMiddleware to be installed before it
func loggerMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqLogger := logger.With("request_id", ctx.MustGet(REQUEST_ID_KEY))
		ctx.Set(LOGGER_KEY, reqLogger)

		start := time.Now()
		path := ctx.Request.URL.Path
		rawQuery := ctx.Request.URL.RawQuery

		// fully process the request
		ctx.Next()

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		if latency > time.Minute {
			latency = latency.Truncate(time.Second)
		}

		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		for _, err := range ctx.Errors.ByType(gin.ErrorTypePrivate) {
			reqLogger.Error(err.Error(), "full", err)
		}

		reqLogger.Info("request handled",
			"start", start.Format(time.RFC3339),
			"end", end.Format(time.RFC3339),
			"latency", latency,
			"status", ctx.Writer.Status(),
			"ip", ctx.ClientIP(),
			"method", ctx.Request.Method,
			"path", path,
		)
	}
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(REQUEST_ID_KEY, uuid.New().String())
	}
}

// this middleware requires authMiddleware to be installed before it
func ensureAdminMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userClaims := getContextUserClaims(ctx)

		if userClaims.AccessLevel != "admin" {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "Insufficient access level (requires administrator privileges)",
				"code":    common.ErrCodeInsufficientAccessLevel,
			})
		}
	}
}

func ensurePackageDBMiddleware(db *packageDB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(PACKAGE_DB_KEY, db)
	}
}

func ensureConfigMiddleware(config *Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(CONFIG_KEY, config)
	}
}

func pgpKeyMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userClaims := getContextUserClaims(ctx)
		config := getContextConfig(ctx)

		// try a few different extensions
		file, err := os.Open(path.Join(config.Keystore.Path, userClaims.Username+".key"))
		if err != nil {
			file, err = os.Open(path.Join(config.Keystore.Path, userClaims.Username+".asc"))
		}
		if err != nil {
			file, err = os.Open(path.Join(config.Keystore.Path, userClaims.Username+".sec"))
		}
		if err != nil {
			file, err = os.Open(path.Join(config.Keystore.Path, userClaims.Username+".enc"))
		}
		if err != nil {
			file, err = os.Open(path.Join(config.Keystore.Path, userClaims.Username+".gpg"))
		}
		if err != nil {
			return
		}

		key, err := crypto.NewKeyFromReader(file)
		if err != nil {
			return
		}

		locked, err := key.IsLocked()
		if err != nil {
			key.ClearPrivateParams()
			return
		}

		if locked {
			// maybe it's an empty passphrase?
			if unlocked, err := key.Unlock([]byte{}); err == nil {
				// great! not great for security, but great for us needing to unlock it!
				key.ClearPrivateParams()
				ctx.Set(PGP_KEY_KEY, unlocked)
				return
			}

			// ok then, we need an actual passphrase

			// first, try a form field
			passphrase := ctx.PostForm("pgp_key_passphrase")
			if passphrase == "" {
				// next, try an env var
				passphrase = os.Getenv("PACRAT_KEY_PASSPHRASE_" + userClaims.Username)
			}
			if passphrase == "" {
				// try to see if it's in the config
				if keyCfg, ok := config.Keys[userClaims.Username]; ok && keyCfg.Passphrase != "" {
					passphrase = keyCfg.Passphrase
				}
			}
			if passphrase == "" {
				key.ClearPrivateParams()
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "PGP key requires passphrase",
					"code":    common.ErrCodeMissingPGPKeyPassphrase,
				})
				return
			}

			unlocked, err := key.Unlock([]byte(passphrase))
			key.ClearPrivateParams()
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "Invalid PGP key passphrase",
					"code":    common.ErrCodeInvalidPGPKeyPassphrase,
				})
				return
			}
			key = unlocked
		}

		ctx.Set(PGP_KEY_KEY, key)
	}
}

func pgpContextMiddleware(pgp *crypto.PGPHandle) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(PGP_CONTEXT_KEY, pgp)
	}
}

func getContextUserClaims(ctx context.Context) UserInfoClaims {
	return ctx.Value(USER_INFO_CLAIMS_KEY).(UserInfoClaims)
}

func getContextPackageDB(ctx context.Context) *packageDB {
	return ctx.Value(PACKAGE_DB_KEY).(*packageDB)
}

func getContextConfig(ctx context.Context) *Config {
	return ctx.Value(CONFIG_KEY).(*Config)
}

func getContextPGPContext(ctx context.Context) *crypto.PGPHandle {
	return ctx.Value(PGP_CONTEXT_KEY).(*crypto.PGPHandle)
}

func main() {
	defaultConfigPath := os.Getenv(CONFIG_ENV_VAR)
	if defaultConfigPath == "" {
		defaultConfigPath = util.TryFileExists("pacrat.toml", "/etc/pacrat.toml")
	}
	configPath := defaultConfigPath

	flag.StringVar(&configPath, "config", defaultConfigPath, "The path to the configuration file to use")
	flag.StringVar(&configPath, "c", defaultConfigPath, "The path to the configuration file to use")

	flag.Parse()

	configDir := path.Dir(configPath)
	configFilename := path.Base(configPath)
	configData, err := fs.ReadFile(os.DirFS(configDir), configFilename)
	if err != nil {
		log.Fatal(err)
	}

	config := DefaultConfig()
	toml.Unmarshal(configData, &config)

	envLogLevel := slog.LevelInfo
	if err := envLogLevel.UnmarshalText([]byte(os.Getenv(LOG_LEVEL_ENV_VAR))); err == nil {
		config.Log.Level = envLogLevel
	}

	if err := os.MkdirAll(path.Dir(config.Log.Path), 0700); err != nil {
		log.Fatal(err)
	}

	logFile, err := os.OpenFile(config.Log.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := logFile.Close(); err != nil && err != os.ErrClosed {
			panic(err)
		}
	}()

	logger := slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stdout, logFile), &slog.HandlerOptions{
		AddSource: true,
		Level:     config.Log.Level,
	}))

	slog.SetDefault(logger)

	logger.Info("starting pacrat")

	logger.Debug("configuration loaded", "config", config)

	if config.Oidc.Endpoint == "" {
		logger.Error("OIDC endpoint must be set to a valid URL (currently empty)", "oidc_endpoint", config.Oidc.Endpoint)
		os.Exit(1)
	}

	if config.Oidc.ClientID == "" {
		logger.Error("OIDC client ID must be set (currently empty)", "oidc_client_id", config.Oidc.ClientID)
		os.Exit(1)
	}

	if config.DB.Name == "" {
		logger.Error("repository name must be set (currently empty)", "db_name", config.DB.Name)
		os.Exit(1)
	}

	if config.Keystore.Path == "" {
		logger.Error("keystore path must be set (currently empty)", "keystore_path", config.Keystore.Path)
		os.Exit(1)
	}

	err = os.MkdirAll(config.DB.Path, 0750)
	if err != nil {
		logger.Error("failed to create repository directory (including parents)", "db_path", config.DB.Path, "error", err)
		os.Exit(1)
	}

	err = os.MkdirAll(config.DB.TemporaryDirectory, 0700)
	if err != nil {
		logger.Error("failed to create temporary directory (including parents)", "tmp_path", config.DB.TemporaryDirectory, "error", err)
		os.Exit(1)
	}

	err = os.MkdirAll(config.Keystore.Path, 0700)
	if err != nil {
		logger.Error("failed to create keystore path directory (including parents)", "keystore_path", config.Keystore.Path, "error", err)
		os.Exit(1)
	}

	config.Oidc.Endpoint = strings.TrimSuffix(config.Oidc.Endpoint, WELLKNOWN_PATH)

	provider, err := oidc.NewProvider(context.Background(), config.Oidc.Endpoint)
	if err != nil {
		logger.Error("failed to initialize OIDC provider information", "error", err)
		os.Exit(1)
	}

	oidcConfig := &oidc.Config{
		ClientID: config.Oidc.ClientID,
	}

	verifier := provider.VerifierContext(context.Background(), oidcConfig)

	pkgDB := &packageDB{
		database: &alp.Database{},
	}

	mainDBFile, err := os.Open(config.DB.MainDBPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("failed to open main DB", "error", err)
		os.Exit(1)
	}

	fileDBFile, err := os.Open(config.DB.FileDBPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("failed to open file DB", "error", err)
		os.Exit(1)
	}

	if mainDBFile != nil && fileDBFile != nil {
		pkgDB.database, err = alp.ReadDatabase(mainDBFile, fileDBFile)
		if err != nil {
			logger.Error("failed to read existing main and file DB", "error", err)
			os.Exit(1)
		}
	} else if mainDBFile != nil {
		logger.Error("existing main DB but missing file DB", "main_db_path", config.DB.MainDBPath, "file_db_path", config.DB.FileDBPath)
		os.Exit(1)
	} else if fileDBFile != nil {
		logger.Warn("existing file DB but missing main DB", "main_db_path", config.DB.MainDBPath, "file_db_path", config.DB.FileDBPath)
		os.Exit(1)
	}

	gin.SetMode(gin.ReleaseMode)

	serverEngine := gin.New()
	serverEngine.Use(requestIDMiddleware(), loggerMiddleware(logger), ensureConfigMiddleware(&config), pgpContextMiddleware(crypto.PGP()), gin.Recovery())
	serverEngine.SetTrustedProxies(config.Server.TrustedProxies)

	serverEngine.GET("/auth_info", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"oidc_endpoint": config.Oidc.Endpoint,
			"client_id":     config.Oidc.ClientID,
		})
	})

	serverEngine.GET("/check_token", authMiddleware(provider, verifier), func(ctx *gin.Context) {
		userClaims := getContextUserClaims(ctx)

		ctx.JSON(http.StatusOK, gin.H{
			"access_level": userClaims.AccessLevel,
		})
	})

	serverEngine.POST("/upload_package", authMiddleware(provider, verifier), ensureAdminMiddleware(), ensurePackageDBMiddleware(pkgDB), pgpKeyMiddleware(), uploadPackage)
	serverEngine.POST("/upload_pgp_key", authMiddleware(provider, verifier), uploadPGPKey)

	if err = serverEngine.Run(":" + strconv.Itoa(config.Server.Port)); err != nil {
		logger.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}
