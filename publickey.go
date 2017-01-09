// Copyright 2016 Ivan (Vanya) A. Sergeev (https://github.com/vsergeev)
// Copyright 2017 The coin-network developers
// License: MIT

package curve

import (
  "golang.org/x/crypto/ripemd160"
	"fmt"
  "bytes"
  "crypto/sha256"
  "math/big"
  "crypto/ecdsa"
)

type PublicKey ecdsa.PublicKey

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

/* DecompressPoint decompresses coordinate x and ylsb (y's least significant bit)
and returns the value of y
source: https://github.com/btcsuite/btcd/blob/807d344fe97072efdf38ac3df053e07f26187a4f/btcec/pubkey.go#L27 */
func (curve *KoblitzCurve) DecompressPoint(x *big.Int, ybit bool) (*big.Int, error) {
  // TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

  // TODO: It is necessary to verify with IsOnCurve(x, y) or ParsePubKey ?

	return y, nil  // TODO return struct Point (x, y)
}

// ToECDSA returns the public key as a *ecdsa.PublicKey.
func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

// ToAddressUncompressed converts a public key to an uncompressed address string.
func (pub *PublicKey) ToAddressUncompressed() (address string) {

  /* Convert the public key to bytes */
  pub_bytes := pub.ToBytesUncompressed()

  /* SHA256 Hash */
  sha256_h := sha256.New()
  sha256_h.Reset()
  sha256_h.Write(pub_bytes)
  pub_hash_1 := sha256_h.Sum(nil)

  /* RIPEMD-160 Hash */
  ripemd160_h := ripemd160.New()
  ripemd160_h.Reset()
  ripemd160_h.Write(pub_hash_1)
  pub_hash_2 := ripemd160_h.Sum(nil)

  /* Convert hash bytes to base58 check encoded sequence */
  address = b58checkencode(0x00, pub_hash_2)

  return address
}

// ToAddress converts a public key to a compressed address string.
func (pub *PublicKey) ToAddress() (address string) {
  /* See https://en.bitcoin.it/w/images/en/9/9b/PubKeyToAddr.png */

  /* Convert the public key to bytes */
  pub_bytes := pub.ToBytes()

  /* SHA256 Hash */
  sha256_h := sha256.New()
  sha256_h.Reset()
  sha256_h.Write(pub_bytes)
  pub_hash_1 := sha256_h.Sum(nil)

  /* RIPEMD-160 Hash */
  ripemd160_h := ripemd160.New()
  ripemd160_h.Reset()
  ripemd160_h.Write(pub_hash_1)
  pub_hash_2 := ripemd160_h.Sum(nil)

  /* Convert hash bytes to base58 check encoded sequence */
  address = b58checkencode(0x00, pub_hash_2)

  return address
}

// ToBytes converts a public key to a 33-byte byte slice with point compression.
func (pub *PublicKey) ToBytes() (b []byte) {
  /* See Certicom SEC1 2.3.3, pg. 10 */

  x := pub.X.Bytes()

  /* Pad X to 32-bytes */
  padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)

  /* Add prefix 0x02 or 0x03 depending on ylsb */
  if pub.Y.Bit(0) == 0 {
    return append([]byte{0x02}, padded_x...)
  }

  return append([]byte{0x03}, padded_x...)
}

// ToBytesUncompressed converts a public key to a 65-byte byte slice without point compression.
func (pub *PublicKey) ToBytesUncompressed() (b []byte) {
  /* See Certicom SEC1 2.3.3, pg. 10 */

  x := pub.X.Bytes()
  y := pub.Y.Bytes()

  /* Pad X and Y coordinate bytes to 32-bytes */
  padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)
  padded_y := append(bytes.Repeat([]byte{0x00}, 32-len(y)), y...)

  /* Add prefix 0x04 for uncompressed coordinates */
  return append([]byte{0x04}, append(padded_x, padded_y...)...)
}

// TODO: Where is it used and what is it used for?
// FromBytes converts a byte slice (either with or without point compression) to a public key.
func (pub *PublicKey) FromBytes(koblitzcurve *KoblitzCurve, b []byte) (err error) {
  /* See Certicom SEC1 2.3.4, pg. 11 */

  if len(b) < 33 {
    return fmt.Errorf("Invalid public key bytes length %d, expected at least 33.", len(b))
  }

  if b[0] == 0x02 || b[0] == 0x03 {
    /* Compressed public key */

    if len(b) != 33 {
      return fmt.Errorf("Invalid public key bytes length %d, expected 33.", len(b))
    }

    // TODO: Is OK ?
    pub.X = new(big.Int).SetBytes(b[1:33])

    ybit := false
    // TODO: This question is correct ?
    if uint(b[0]&0x1) == 1 {
      ybit = true
    }

    Y, err := koblitzcurve.DecompressPoint(new(big.Int).SetBytes(b[1:33]), ybit)

    if err != nil {
      return fmt.Errorf("Invalid compressed public key bytes, decompression error: %v", err)
    }

    pub.Y = Y

  } else if b[0] == 0x04 {
    /* Uncompressed public key */

    if len(b) != 65 {
      return fmt.Errorf("Invalid public key bytes length %d, expected 65.", len(b))
    }

    pub.X = new(big.Int).SetBytes(b[1:33])
    pub.Y = new(big.Int).SetBytes(b[33:65])

    /* Check that the point is on the curve */
    if !koblitzcurve.IsOnCurve(pub.X, pub.Y) {
      return fmt.Errorf("Invalid public key bytes: point not on curve.")
    }

  } else {
    return fmt.Errorf("Invalid public key prefix byte 0x%02x, expected 0x02, 0x03, or 0x04.", b[0])
  }

  return nil
}
