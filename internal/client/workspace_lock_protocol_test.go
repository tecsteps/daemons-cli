//go:build e22_protocol && go1.27

package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// This opt-in standard-library oracle does not raise the CLI's Go 1.24 baseline.
// S7 must run the same fixtures against the approved runtime HPKE dependency.
func TestWorkspaceLockProtocol(t *testing.T) {
	directory := os.Getenv("E22_VECTOR_DIR")
	if directory == "" {
		t.Fatal("E22_VECTOR_DIR must name E22's vectors directory")
	}
	unhex := func(s string) []byte {
		v, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	unbase64 := func(s string) []byte {
		v, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	load := func(name string, target any) {
		v, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(v, target); err != nil {
			t.Fatal(err)
		}
	}
	var rfc struct {
		SkRm, Enc, Info string
		Encryptions     []struct{ AAD, Ct, Pt string }
		Exports         []struct {
			Context string `json:"exporter_context"`
			Length  int    `json:"L"`
			Value   string `json:"exported_value"`
		}
	}
	load("rfc9180-p256.json", &rfc)
	private, err := ecdh.P256().NewPrivateKey(unhex(rfc.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	newRecipient := func(enc, info []byte) *hpke.Recipient {
		r, err := hpke.NewRecipient(enc, key, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	t.Run("CFRG encryption and exporters", func(t *testing.T) {
		r := newRecipient(unhex(rfc.Enc), unhex(rfc.Info))
		for _, item := range rfc.Encryptions {
			plain, err := r.Open(unhex(item.AAD), unhex(item.Ct))
			if err != nil || !bytes.Equal(plain, unhex(item.Pt)) {
				t.Fatal("CFRG open mismatch", err)
			}
		}
		for _, item := range rfc.Exports {
			value, err := r.Export(string(unhex(item.Context)), item.Length)
			if err != nil || !bytes.Equal(value, unhex(item.Value)) {
				t.Fatal("CFRG exporter mismatch", err)
			}
		}
	})
	var fixture map[string]json.RawMessage
	load("workspace-lock-v1.json", &fixture)
	str := func(name string) string {
		var value string
		if err := json.Unmarshal(fixture[name], &value); err != nil {
			t.Fatal(err)
		}
		return value
	}

	t.Run("organization password verifier", func(t *testing.T) {
		value, err := pbkdf2.Key(sha256.New, str("organization_password"), unhex(str("organization_kdf_salt")), 600000, 32)
		if err != nil || !bytes.Equal(value, unhex(str("organization_verifier"))) {
			t.Fatal("organization verifier differs from Node/WebCrypto", err)
		}
	})
	var frame struct{ Enc, Ciphertext string }
	if err := json.Unmarshal([]byte(str("frame")), &frame); err != nil {
		t.Fatal(err)
	}
	newGuest := func(info string) *hpke.Recipient { return newRecipient(unbase64(frame.Enc), []byte(info)) }
	aad := []byte(str("canonical_challenge"))
	ciphertext := unbase64(frame.Ciphertext)
	t.Run("E22 request response and tamper", func(t *testing.T) {
		guest := newGuest(str("info"))
		plain, err := guest.Open(aad, ciphertext)
		if err != nil || string(plain) != str("plaintext") {
			t.Fatal("E22 request mismatch", err)
		}
		responseKey, err := guest.Export("dr.workspace-lock.response.key.v1", 16)
		if err != nil || !bytes.Equal(responseKey, unhex(str("response_key"))) {
			t.Fatal("response key mismatch", err)
		}
		nonce, err := guest.Export("dr.workspace-lock.response.nonce.v1", 12)
		if err != nil || !bytes.Equal(nonce, unhex(str("response_nonce"))) {
			t.Fatal("response nonce mismatch", err)
		}
		block, err := aes.NewCipher(responseKey)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(str("frame")))
		responseAAD := append(append([]byte{}, aad...), digest[:]...)
		if !bytes.Equal(responseAAD, unhex(str("response_aad"))) {
			t.Fatal("response AAD mismatch")
		}
		sealed := aead.Seal(nil, nonce, []byte(str("response_plaintext")), responseAAD)
		if !bytes.Equal(sealed, unhex(str("response_ciphertext"))) {
			t.Fatal("Go response differs from JS vector")
		}
		sealed[len(sealed)-1] ^= 1
		if _, err := aead.Open(nil, nonce, sealed, responseAAD); err == nil {
			t.Fatal("tampered response accepted")
		}
		if _, err := newGuest("wrong-info").Open(aad, ciphertext); err == nil {
			t.Fatal("wrong info accepted")
		}
		if _, err := newGuest(str("info")).Open(append(append([]byte{}, aad...), 'x'), ciphertext); err == nil {
			t.Fatal("wrong AAD accepted")
		}
		altered := append([]byte{}, ciphertext...)
		altered[0] ^= 1
		if _, err := newGuest(str("info")).Open(aad, altered); err == nil {
			t.Fatal("tampered request accepted")
		}
	})
	t.Run("P1363 identity pin and signature domain", func(t *testing.T) {
		var challenge struct {
			PublicKey string `json:"identity_public_key"`
		}
		if err := json.Unmarshal(fixture["challenge"], &challenge); err != nil {
			t.Fatal(err)
		}
		pub := unbase64(challenge.PublicKey)
		pin := sha256.Sum256(pub)
		if hex.EncodeToString(pin[:]) != str("pin") {
			t.Fatal("pin mismatch")
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), pub)
		if x == nil {
			t.Fatal("invalid public key")
		}
		identity := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		sig := unhex(str("signature"))
		if len(sig) != 64 {
			t.Fatal("invalid P1363 length")
		}
		verify := func(domain string) bool {
			digest := sha256.Sum256(append([]byte(domain+"\x00"), aad...))
			return ecdsa.Verify(identity, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}
		if !verify("dr.workspace-lock.challenge.v1") || verify("dr.workspace-lock.device.v1") {
			t.Fatal("signature domain mismatch")
		}
	})
}
