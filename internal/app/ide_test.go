package app

import "testing"

func TestIDEAliasIsOriginNamespaced(t *testing.T) {
	a := originHash("https://one.example/api/v1")
	b := originHash("https://two.example/api/v1")
	if a == b {
		t.Fatal("control-plane host hashes collided")
	}
}
