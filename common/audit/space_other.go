//go:build !linux

package audit

import "errors"

func freeBytes(string) (uint64, error) {
	return 0, errors.New("audit free-space threshold requires Linux")
}
