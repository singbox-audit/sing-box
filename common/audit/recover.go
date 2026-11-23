package audit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// readFrame reads exactly one frame without consuming bytes belonging to its
// successor. Verify its checksum before including the frame in a recovered volume.
func readFrame(r *bufio.Reader) ([]byte, error) {
	header, err := r.Peek(18)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(header) == 0 {
		return nil, io.EOF
	}
	var h zstd.Header
	if err = h.Decode(header); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	if h.Skippable {
		return nil, errors.New("unexpected skippable frame")
	}
	frame := append([]byte(nil), header[:h.HeaderSize]...)
	r.Discard(h.HeaderSize)
	for {
		var block [3]byte
		if _, err = io.ReadFull(r, block[:]); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		n := binary.LittleEndian.Uint32([]byte{block[0], block[1], block[2], 0})
		size := int(n >> 3)
		switch (n >> 1) & 3 {
		case 1:
			size = 1
		case 3:
			return nil, errors.New("invalid block type")
		}
		if n&1 != 0 && h.HasCheckSum {
			size += 4
		}
		if len(frame)+size > 8<<20 {
			return nil, errors.New("oversized audit frame")
		}
		frame = append(frame, block[:]...)
		offset := len(frame)
		frame = append(frame, make([]byte, size)...)
		if _, err = io.ReadFull(r, frame[offset:]); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if n&1 != 0 {
			return frame, nil
		}
	}
}

func recoverVolumes(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(16<<20), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return err
	}
	defer decoder.Close()
	for _, f := range files {
		name := f.Name()
		if !f.Type().IsRegular() || !strings.HasSuffix(name, ".jsonl.zst.partial") || !(strings.HasPrefix(name, "conn_") || strings.HasPrefix(name, "dns_")) {
			continue
		}
		if err = recoverVolume(filepath.Join(dir, name), decoder); err != nil {
			return fmt.Errorf("recover %s: %w", name, err)
		}
	}
	return nil
}

func recoverVolume(path string, d *zstd.Decoder) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var good int64
	for {
		frame, e := readFrame(r)
		if e == io.EOF {
			break
		}
		if e == nil {
			_, e = d.DecodeAll(frame, nil)
		}
		if e != nil {
			var pathError *os.PathError
			if errors.As(e, &pathError) {
				return e
			}
			// Preserve the damaged suffix before truncation. Repeating recovery
			// after an interruption recreates the same suffix from the original.
			tail, err := os.OpenFile(path+".damaged", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = f.Seek(good, io.SeekStart)
			if err == nil {
				_, err = io.Copy(tail, f)
			}
			if err = errors.Join(err, tail.Sync(), tail.Close()); err != nil {
				return err
			}
			if err = syncDirectory(filepath.Dir(path)); err != nil {
				return err
			}
			if err = f.Truncate(good); err != nil {
				return err
			}
			break
		}
		good += int64(len(frame))
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if good == 0 {
		err = os.Remove(path)
	} else {
		err = os.Rename(path, strings.TrimSuffix(path, ".partial"))
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
