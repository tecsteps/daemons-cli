package app

import "testing"

func TestIDEAliasIsOriginNamespaced(t *testing.T) {
	a := originHash("https://one.example/api/v1")
	b := originHash("https://two.example/api/v1")
	if a == b {
		t.Fatal("control-plane host hashes collided")
	}
}

func TestIDETargetRejectsUncertifiedClientsAndFolderEscapes(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	for _, editor := range []string{"code", "cursor"} {
		if err := validateIDETarget(id, editor, "default"); err != nil {
			t.Fatal(err)
		}
		for _, folder := range []string{"../secret", "/root", "a?query", "a#fragment", "a%2fb"} {
			if validateIDETarget(id, editor, folder) == nil {
				t.Fatal("accepted unsafe folder")
			}
		}
	}
	for _, editor := range []string{"zed", "jetbrains"} {
		if validateIDETarget(id, editor, "default") == nil {
			t.Fatal("accepted uncertified IDE")
		}
	}
}
