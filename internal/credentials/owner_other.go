//go:build !darwin && !linux

package credentials

import "io/fs"

func validateOwner(_ fs.FileInfo) error {
	return nil
}
