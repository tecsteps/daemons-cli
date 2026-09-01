//go:build darwin || linux

package credentials

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func validateOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("owner must be the current user")
	}

	return nil
}
