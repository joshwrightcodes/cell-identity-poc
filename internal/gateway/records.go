package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// MaxRecordBytes is the largest record envelope that ApplySync stores.
const MaxRecordBytes = 64 << 10

// The refusals of ApplySync besides the errors of package spec and record.
var (
	// ErrSpecOld means the spec revision is below the stored spec revision.
	ErrSpecOld = errors.New("spec revision is below the stored revision")
	// ErrSpecConflict means another spec has the stored spec revision.
	ErrSpecConflict = errors.New("another spec has the stored revision")
	// ErrRecordMissing means the bundle has no record for an indexed cell.
	ErrRecordMissing = errors.New("bundle has no record for an indexed cell")
	// ErrRecordOld means a record is below the mark of its cell.
	ErrRecordOld = errors.New("record revision is below its mark")
	// ErrRecordConflict means another record has the revision of the mark of its cell.
	ErrRecordConflict = errors.New("another record has the revision of the mark")
	// ErrEnvMismatch means the spec env differs from the env of the stored spec.
	ErrEnvMismatch = errors.New("spec env differs from the stored spec")
	// ErrMarkUnlisted means a cell with a mark is in neither list of the spec.
	ErrMarkUnlisted = errors.New("cell has a mark and is in neither list of the spec")
	// ErrRetiredBelowMark means a retired revision is below the mark of its cell.
	ErrRetiredBelowMark = errors.New("retired revision is below the mark of the cell")
	// ErrRecordUnindexed means the bundle has a record that the spec does not index.
	ErrRecordUnindexed = errors.New("bundle has a record that the spec does not index")
)

// KeyFingerprint returns the lowercase hex SHA-256 of the pinned keys, joined in order.
func KeyFingerprint(keys []ed25519.PublicKey) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write(k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ApplySync verifies the spec and takes the records that the spec indexes with the same digest.
// A cell mark is the highest revision that the store has seen for the cell, and it never drops
// while the pinned keys stay. When the fingerprint of keys differs from the stored one, the store
// first clears its marks, records and spec, and logs state_reset. A refused sync changes nothing,
// except that a record below its mark counts as record_old.
func (s *Store) ApplySync(ctx context.Context, specEnvelope []byte, records map[string]json.RawMessage, keys []ed25519.PublicKey) error {
	var refusal error
	err := s.tx(ctx, func(tx *sql.Tx) error {
		refusal = nil
		if err := s.resetOnKeyChange(tx, KeyFingerprint(keys)); err != nil {
			return err
		}
		var err error
		if refusal, err = s.applySync(tx, specEnvelope, records, keys); err != nil {
			return err
		}
		if errors.Is(refusal, ErrRecordOld) {
			return s.bumpRecordOld(tx)
		}
		if refusal != nil {
			return refusal
		}
		return nil
	})
	if err != nil {
		return err
	}
	return refusal
}

func (s *Store) resetOnKeyChange(tx *sql.Tx, fp string) error {
	stored, err := metaString(tx, "key_sha256")
	if err != nil {
		return err
	}
	if stored == fp {
		return nil
	}
	if stored != "" {
		s.log.Warn("state_reset", "stored_key_sha256", stored, "pinned_key_sha256", fp)
	}
	for _, q := range []string{`DELETE FROM records`, `DELETE FROM marks`, `DELETE FROM meta WHERE key IN ('spec_envelope', 'spec_sha256', 'spec_env', 'spec_epoch', 'spec_counter')`} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return setMeta(tx, "key_sha256", fp)
}

// applySync returns a refusal as its first value and a store failure as its second. It writes
// nothing before every check has passed.
func (s *Store) applySync(tx *sql.Tx, specEnvelope []byte, records map[string]json.RawMessage, keys []ed25519.PublicKey) (refusal, err error) {
	sp, payload, verr := spec.Verify(specEnvelope, keys)
	if verr != nil {
		return verr, nil
	}
	digest := spec.RecordDigest(payload)
	curEpoch, err := metaInt(tx, "spec_epoch")
	if err != nil {
		return nil, err
	}
	curCounter, err := metaInt(tx, "spec_counter")
	if err != nil {
		return nil, err
	}
	curSHA, err := metaString(tx, "spec_sha256")
	if err != nil {
		return nil, err
	}
	curEnv, err := metaString(tx, "spec_env")
	if err != nil {
		return nil, err
	}
	if curEnv != "" && curEnv != sp.Env {
		return fmt.Errorf("%w: spec env %q, stored %q", ErrEnvMismatch, sp.Env, curEnv), nil
	}
	switch sp.Revision.Compare(spec.Revision{Epoch: uint64(curEpoch), Counter: uint64(curCounter)}) {
	case -1:
		return fmt.Errorf("%w: %v", ErrSpecOld, sp.Revision), nil
	case 0:
		if curSHA != "" && curSHA != digest {
			return fmt.Errorf("%w: %v", ErrSpecConflict, sp.Revision), nil
		}
	}

	marks := map[string]spec.Revision{}
	held := map[string]string{}
	if err := scanRows(tx, `SELECT name, epoch, counter FROM marks`, func(r *sql.Rows) error {
		var name string
		var rev spec.Revision
		if err := r.Scan(&name, &rev.Epoch, &rev.Counter); err != nil {
			return err
		}
		marks[name] = rev
		return nil
	}); err != nil {
		return nil, err
	}
	if err := scanRows(tx, `SELECT name, digest FROM records`, func(r *sql.Rows) error {
		var name, d string
		if err := r.Scan(&name, &d); err != nil {
			return err
		}
		held[name] = d
		return nil
	}); err != nil {
		return nil, err
	}

	retiredRev := make(map[string]spec.Revision, len(sp.Retired))
	for _, r := range sp.Retired {
		retiredRev[r.Name] = r.Revision
	}
	listed := make(map[string]bool, len(sp.Cells))
	for _, e := range sp.Cells {
		listed[e.Name] = true
	}
	for name, mark := range marks {
		if r, ok := retiredRev[name]; ok {
			if r.Compare(mark) < 0 {
				return fmt.Errorf("%w: %q retired at %v, mark %v", ErrRetiredBelowMark, name, r, mark), nil
			}
		} else if !listed[name] {
			return fmt.Errorf("%w: %q, mark %v", ErrMarkUnlisted, name, mark), nil
		}
	}

	type accepted struct {
		envelope []byte
		cell     []byte
		entry    spec.Entry
	}
	take := make([]accepted, 0, len(sp.Cells))
	indexed := map[string]bool{}
	for _, e := range sp.Cells {
		indexed[e.Name] = true
		raw, ok := records[e.Name]
		if !ok {
			return fmt.Errorf("%w: %q", ErrRecordMissing, e.Name), nil
		}
		if len(raw) > MaxRecordBytes {
			return fmt.Errorf("record of %q has %d bytes, the limit is %d", e.Name, len(raw), MaxRecordBytes), nil
		}
		c, recPayload, verr := record.VerifyWithPayload(raw, keys)
		if verr != nil {
			return fmt.Errorf("record of %q: %w", e.Name, verr), nil
		}
		if cerr := sp.CheckRecord(e.Name, c, recPayload); cerr != nil {
			return cerr, nil
		}
		if mark, seen := marks[e.Name]; seen {
			switch e.Revision.Compare(mark) {
			case -1:
				return fmt.Errorf("%w: %q revision %v, mark %v", ErrRecordOld, e.Name, e.Revision, mark), nil
			case 0:
				d, present := held[e.Name]
				switch {
				case !present:
					return fmt.Errorf("%w: %q equals the mark of a cell with no record", ErrRecordOld, e.Name), nil
				case d != e.RecordSHA256:
					return fmt.Errorf("%w: %q at %v", ErrRecordConflict, e.Name, e.Revision), nil
				}
			}
		}
		cellJSON, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		take = append(take, accepted{envelope: raw, cell: cellJSON, entry: e})
	}
	for name := range records {
		if !indexed[name] {
			return fmt.Errorf("%w: %q", ErrRecordUnindexed, name), nil
		}
	}

	if _, err := tx.Exec(`DELETE FROM records`); err != nil {
		return nil, err
	}
	raise := func(name string, rev spec.Revision) error {
		if mark, seen := marks[name]; seen && rev.Compare(mark) <= 0 {
			return nil
		}
		marks[name] = rev
		_, err := tx.Exec(`INSERT INTO marks (name, epoch, counter) VALUES (?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET epoch = excluded.epoch, counter = excluded.counter`, name, rev.Epoch, rev.Counter)
		return err
	}
	for _, a := range take {
		if _, err := tx.Exec(`INSERT INTO records (name, envelope, cell, epoch, counter, digest) VALUES (?, ?, ?, ?, ?, ?)`,
			a.entry.Name, []byte(a.envelope), a.cell, a.entry.Revision.Epoch, a.entry.Revision.Counter, a.entry.RecordSHA256); err != nil {
			return nil, err
		}
		if err := raise(a.entry.Name, a.entry.Revision); err != nil {
			return nil, err
		}
	}
	for _, r := range sp.Retired {
		if err := raise(r.Name, r.Revision); err != nil {
			return nil, err
		}
	}
	for k, v := range map[string]any{"spec_envelope": []byte(specEnvelope), "spec_sha256": digest, "spec_env": sp.Env,
		"spec_epoch": sp.Revision.Epoch, "spec_counter": sp.Revision.Counter} {
		if err := setMeta(tx, k, v); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Cell returns the verified record of the named cell. A store failure is an error, and an unknown
// cell is found false.
func (s *Store) Cell(ctx context.Context, name string) (record.Cell, bool, error) {
	var c record.Cell
	var found bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var body []byte
		err := tx.QueryRow(`SELECT cell FROM records WHERE name = ?`, name).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return json.Unmarshal(body, &c)
	})
	if err != nil {
		return record.Cell{}, false, fmt.Errorf("read record of %q: %w", name, err)
	}
	return c, found, nil
}

// SetCells replaces the cell information with cells. A cell whose nonce changes keeps the old
// nonce as its previous one, and a cell that is not in cells is forgotten.
func (s *Store) SetCells(ctx context.Context, cells []mgmtapi.CellInfo) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		old := map[string][2][]byte{}
		if err := scanRows(tx, `SELECT name, latest, previous FROM cell_info`, func(r *sql.Rows) error {
			var name string
			var latest, prev []byte
			if err := r.Scan(&name, &latest, &prev); err != nil {
				return err
			}
			old[name] = [2][]byte{latest, prev}
			return nil
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM cell_info`); err != nil {
			return err
		}
		for _, c := range cells {
			latest, err := json.Marshal(c)
			if err != nil {
				return err
			}
			var prev []byte
			if o, ok := old[c.Name]; ok {
				prev = o[1]
				var was mgmtapi.CellInfo
				if err := json.Unmarshal(o[0], &was); err != nil {
					return err
				}
				if was.Nonce != c.Nonce {
					prev = o[0]
				}
			}
			if _, err := tx.Exec(`INSERT INTO cell_info (name, latest, previous) VALUES (?, ?, ?)`, c.Name, latest, prev); err != nil {
				return err
			}
		}
		return nil
	})
}

// CellInfo returns the latest and previous information of a cell. previous is the zero value when
// the cell has no earlier nonce. A store failure is an error, and an unknown cell is ok false.
func (s *Store) CellInfo(ctx context.Context, name string) (latest, previous mgmtapi.CellInfo, ok bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var l, p []byte
		err := tx.QueryRow(`SELECT latest, previous FROM cell_info WHERE name = ?`, name).Scan(&l, &p)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(l, &latest); err != nil {
			return err
		}
		if p != nil {
			if err := json.Unmarshal(p, &previous); err != nil {
				return err
			}
		}
		ok = true
		return nil
	})
	if err != nil {
		return mgmtapi.CellInfo{}, mgmtapi.CellInfo{}, false, fmt.Errorf("read cell info of %q: %w", name, err)
	}
	return latest, previous, ok, nil
}
