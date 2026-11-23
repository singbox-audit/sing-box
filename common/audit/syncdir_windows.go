package audit

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func syncDirectory(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// FlushFileBuffers requires write access. BACKUP_SEMANTICS opens the
	// directory itself, and the share flags permit concurrent spool operations.
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == nil {
		err = errors.Join(windows.FlushFileBuffers(handle), windows.CloseHandle(handle))
	}
	if err != nil {
		return &os.PathError{Op: "sync directory", Path: path, Err: err}
	}
	return nil
}
