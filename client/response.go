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
