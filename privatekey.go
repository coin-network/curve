// Copyright 2016 Ivan (Vanya) A. Sergeev (https://github.com/vsergeev)
// Copyright 2017 The coin-network developers
// License: MIT

package curve

import (
	"fmt"
  "bytes"
  "math/big"
	"crypto/rand"
  "crypto/ecdsa"
	"crypto/elliptic"
)

type PrivateKey ecdsa.PrivateKey

// GenerateKey generate PublicKey/PrivateKey from KoblitzCurve
func NewPrivateKey(koblitzcurve elliptic.Curve) (*PrivateKey, error) {

  //privkeyCurve := new(ecdsa.PrivateKey)
  privkeyCurve, err := ecdsa.GenerateKey(koblitzcurve, rand.Reader)

	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(privkeyCurve), nil
}

// PubKey returns the PublicKey corresponding to this private key.
func (p *PrivateKey) PubKey() *PublicKey {
	return (*PublicKey)(&p.PublicKey)
}

// ToECDSA returns the private key as a *ecdsa.PrivateKey.
func (p *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return (*ecdsa.PrivateKey)(p)
}

// Sign generates an ECDSA signature for the provided hash (which should be the result
// of hashing a larger message) using the private key. Produced signature
// is deterministic (same message and same key yield the same signature) and canonical
// in accordance with RFC6979 and BIP0062.
func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(p, hash)
}

// ToBytes converts a Bitcoin private key to a 32-byte byte slice.
func (priv *PrivateKey) ToBytes() (b []byte) {
  d := priv.D.Bytes()

  /* Pad D to 32 bytes */
  padded_d := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

  return padded_d
}

// FromBytes converts a 32-byte byte slice to a Bitcoin private key and derives the corresponding public key.
func (priv *PrivateKey) FromBytes(b []byte) (err error) {

  if len(b) != 32 {
    return fmt.Errorf("Invalid private key bytes length %d, expected 32.", len(b))
  }

  priv.D = new(big.Int).SetBytes(b)

  /* Public returns the public key corresponding to priv.  */
  //priv.Public() // TODO: ?? priv.derive() see: https://github.com/vsergeev/btckeygenie/blob/master/btckey/btckey.go#L48

  return nil
}

// ToWIF converts a Bitcoin private key to a Wallet Import Format string.
func (priv *PrivateKey) ToWIF() (wif string) {
  /* See https://en.bitcoin.it/wiki/Wallet_import_format */

  /* Convert the private key to bytes */
  priv_bytes := priv.ToBytes()

  /* Convert bytes to base-58 check encoded string with version 0x80 */
  wif = b58checkencode(0x80, priv_bytes)

  return wif
}

// ToWIFC converts a private key to a Wallet Import Format string with the public key compressed flag.
func (priv *PrivateKey) ToWIFC() (wifc string) {
  /* See https://en.bitcoin.it/wiki/Wallet_import_format */

  /* Convert the private key to bytes */
  priv_bytes := priv.ToBytes()

  /* Append 0x01 to tell Bitcoin wallet to use compressed public keys */
  priv_bytes = append(priv_bytes, []byte{0x01}...)

  /* Convert bytes to base-58 check encoded string with version 0x80 */
  wifc = b58checkencode(0x80, priv_bytes)

  return wifc
}

// FromWIF converts a Wallet Import Format string to a Bitcoin private key and derives the corresponding public key.
func (priv *PrivateKey) FromWIF(wif string) (err error) {
  /* See https://en.bitcoin.it/wiki/Wallet_import_format */

  /* Base58 Check Decode the WIF string */
  ver, priv_bytes, err := b58checkdecode(wif)
  if err != nil {
    return err
  }

  /* Check that the version byte is 0x80 */
  if ver != 0x80 {
    return fmt.Errorf("Invalid WIF version 0x%02x, expected 0x80.", ver)
  }

  /* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) and strip it off */
  if len(priv_bytes) == 33 {
    if priv_bytes[len(priv_bytes)-1] != 0x01 {
      return fmt.Errorf("Invalid private key, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
    }
    priv_bytes = priv_bytes[0:32]
  }

  /* Convert from bytes to a private key */
  err = priv.FromBytes(priv_bytes)
  if err != nil {
    return err
  }

  /* Derive public key from private key */
  //priv.Public() // TODO: ?? priv.derive() see: https://github.com/vsergeev/btckeygenie/blob/master/btckey/btckey.go#L48

  return nil
}

// CheckWIF checks that string wif is a valid Wallet Import Format or Wallet Import Format Compressed string. If it is not, err is populated with the reason.
func CheckWIF(wif string) (valid bool, err error) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Base58 Check Decode the WIF string */
	ver, priv_bytes, err := b58checkdecode(wif)
	if err != nil {
		return false, err
	}

	/* Check that the version byte is 0x80 */
	if ver != 0x80 {
		return false, fmt.Errorf("Invalid WIF version 0x%02x, expected 0x80.", ver)
	}

	/* Check that private key bytes length is 32 or 33 */
	if len(priv_bytes) != 32 && len(priv_bytes) != 33 {
		return false, fmt.Errorf("Invalid private key bytes length %d, expected 32 or 33.", len(priv_bytes))
	}

	/* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) */
	if len(priv_bytes) == 33 && priv_bytes[len(priv_bytes)-1] != 0x01 {
		return false, fmt.Errorf("Invalid private key bytes, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
	}

	return true, nil
}
