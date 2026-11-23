//go:build !windows

package audit

import (
	"errors"
	"os"
)

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
