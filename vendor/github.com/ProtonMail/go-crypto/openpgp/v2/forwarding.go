// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package v2

import (
	goerrors "errors"

	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// NewForwardingEntity generates a new forwardee key and derives the proxy parameters from the entity e.
// If strict, it will return an error if encryption-capable non-revoked subkeys with a wrong algorithm are found,
// instead of ignoring them
func (e *Entity) NewForwardingEntity(
	name, comment, email string, config *packet.Config, strict bool,
) (
	forwardeeKey *Entity, instances []packet.ForwardingInstance, err error,
) {
	if e.PrimaryKey.Version != 4 {
		return nil, nil, errors.InvalidArgumentError("unsupported key version")
	}

	now := config.Now()

	if _, err = e.VerifyPrimaryKey(now); err != nil {
		return nil, nil, err
	}

	// Generate a new Primary key for the forwardee
	config.Algorithm = packet.PubKeyAlgoEdDSA
	config.Curve = packet.Curve25519

	forwardeePrimaryPrivRaw, err := newSigner(config)
	if err != nil {
		return nil, nil, err
	}

	primary := packet.NewSignerPrivateKey(now, forwardeePrimaryPrivRaw)

	forwardeeKey = &Entity{
		PrimaryKey: &primary.PublicKey,
		PrivateKey: primary,
		Identities: make(map[string]*Identity),
		Subkeys:    []Subkey{},
	}

	keyProperties := selectKeyProperties(now, config, primary)
	err = forwardeeKey.addUserId(userIdData{name, comment, email}, config, keyProperties)
	if err != nil {
		return nil, nil, err
	}

	// Init empty instances
	instances = []packet.ForwardingInstance{}

	// Handle all forwarder subkeys
	for _, forwarderSubKey := range e.Subkeys {
		// Filter flags
		if !forwarderSubKey.PublicKey.PubKeyAlgo.CanEncrypt() {
			continue
		}

		forwarderSubKeySelfSig, err := forwarderSubKey.Verify(now)
		// Filter expiration & revokal
		if err != nil {
			continue
		}

		if forwarderSubKey.PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
			if strict {
				return nil, nil, errors.InvalidArgumentError("encryption subkey is not algorithm 18 (ECDH)")
			} else {
				continue
			}
		}

		forwarderEcdhKey, ok := forwarderSubKey.PrivateKey.PrivateKey.(*ecdh.PrivateKey)
		if !ok {
			return nil, nil, errors.InvalidArgumentError("malformed key")
		}

		err = forwardeeKey.addEncryptionSubkey(config, now, 0)
		if err != nil {
			return nil, nil, err
		}

		forwardeeSubKey := forwardeeKey.Subkeys[len(forwardeeKey.Subkeys)-1]
		forwardeeSubKeySelfSig := forwardeeSubKey.Bindings[0].Packet

		forwardeeEcdhKey, ok := forwardeeSubKey.PrivateKey.PrivateKey.(*ecdh.PrivateKey)
		if !ok {
			return nil, nil, goerrors.New("wrong forwarding sub key generation")
		}

		instance := packet.ForwardingInstance{
			KeyVersion:           4,
			ForwarderFingerprint: forwarderSubKey.PublicKey.Fingerprint,
		}

		instance.ProxyParameter, err = ecdh.DeriveProxyParam(forwarderEcdhKey, forwardeeEcdhKey)
		if err != nil {
			return nil, nil, err
		}

		kdf := ecdh.KDF{
			Version: ecdh.KDFVersionForwarding,
			Hash:    forwarderEcdhKey.KDF.Hash,
			Cipher:  forwarderEcdhKey.KDF.Cipher,
		}

		// If deriving a forwarding key from a forwarding key
		if forwarderSubKeySelfSig.FlagForward {
			if forwarderEcdhKey.KDF.Version != ecdh.KDFVersionForwarding {
				return nil, nil, goerrors.New("malformed forwarder key")
			}
			kdf.ReplacementFingerprint = forwarderEcdhKey.KDF.ReplacementFingerprint
		} else {
			kdf.ReplacementFingerprint = forwarderSubKey.PublicKey.Fingerprint
		}

		err = forwardeeSubKey.PublicKey.ReplaceKDF(kdf)
		if err != nil {
			return nil, nil, err
		}

		// Extract fingerprint after changing the KDF
		instance.ForwardeeFingerprint = forwardeeSubKey.PublicKey.Fingerprint

		// 0x04 - This key may be used to encrypt communications.
		forwardeeSubKeySelfSig.FlagEncryptCommunications = false

		// 0x08 - This key may be used to encrypt storage.
		forwardeeSubKeySelfSig.FlagEncryptStorage = false

		// 0x10 - The private component of this key may have been split by a secret-sharing mechanism.
		forwardeeSubKeySelfSig.FlagSplitKey = true

		// 0x40 - This key may be used for forwarded communications.
		forwardeeSubKeySelfSig.FlagForward = true

		err = forwardeeSubKeySelfSig.SignKey(forwardeeSubKey.PublicKey, forwardeeKey.PrivateKey, config)
		if err != nil {
			return nil, nil, err
		}

		// Append each valid instance to the list
		instances = append(instances, instance)
	}

	if len(instances) == 0 {
		return nil, nil, errors.InvalidArgumentError("no valid subkey found")
	}

	return forwardeeKey, instances, nil
}
