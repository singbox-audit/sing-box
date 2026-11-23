package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/uuid/v5"
)

// Persist the previous generation's closure before publishing the next ID.
// On replay the closure has the same (conn_id, seq) and can be deduplicated.
func (r *Recorder) startRun() error {
	path := filepath.Join(r.directory, ".run-id")
	raw, err := os.ReadFile(path)
	if err == nil {
		old, err := uuid.FromString(string(bytes.TrimSpace(raw)))
		if err != nil {
			return err
		}
		now := time.Now()
		event := connectionEvent{ID: old.String(), RunID: old.String(), Time: now.UnixMilli(), Type: "run_closed"}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err = r.appendFrame("conn", now.UTC().Truncate(time.Hour), r.encoder.EncodeAll(append(data, '\n'), nil)); err != nil {
			return err
		}
		if err = r.seal("conn"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	r.runID = id.String()
	f, err := os.CreateTemp(r.directory, ".run-id-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(r.runID + "\n")
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(r.directory)
}
