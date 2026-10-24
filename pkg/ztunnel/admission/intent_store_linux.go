// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/lock"
)

var (
	errRequiredInvalid       = errors.New("invalid required workload intent")
	errRequiredConflict      = errors.New("required sandbox needs exact retirement before replacement")
	errRequiredClosed        = errors.New("required intent store is closed")
	errRequiredUnsafe        = errors.New("unsafe required intent store")
	errRequiredIndeterminate = errors.New("required intent persistence is indeterminate; restart required")
)

// RequiredIdentity contains intent and the exact sandbox identity verified by
// admission. It contains no readiness, capture, certificate or protocol ACKs.
// The store does not perform Kubernetes or cryptographic identity verification.
type RequiredIdentity struct {
	ClusterID      uint32 `json:"clusterID"`
	NodeName       string `json:"nodeName"`
	Namespace      string `json:"namespace"`
	NamespaceUID   string `json:"namespaceUID"`
	PodName        string `json:"podName"`
	PodUID         string `json:"podUID"`
	ServiceAccount string `json:"serviceAccount"`
	EndpointID     uint16 `json:"endpointID"`
	ContainerID    string `json:"containerID"`
	NetnsPath      string `json:"netnsPath"`
	NetnsDevice    uint64 `json:"netnsDevice"`
	NetnsInode     uint64 `json:"netnsInode"`
	NetnsCookie    uint64 `json:"netnsCookie"`
}

// RequiredIntent is a durable request to require protection, never proof that
// any downstream configuration has been acknowledged or installed.
type RequiredIntent struct {
	SchemaVersion int `json:"schemaVersion"`
	RequiredIdentity
	Incarnation string `json:"incarnation"`
}

type intentOperations struct {
	writeFile func(*os.File, []byte) error
	syncFile  func(*os.File) error
	rename    func(string, string) error
	syncDir   func() error
}

// IntentStore has one exclusive owner. Every operation is relative to held
// directory descriptors; a replaced directory path invalidates this store.
// Construct it only after Cilium has created its trusted StateDir. Recovery
// callers must fence packets and freshly validate live identities before use.
type IntentStore struct {
	mu        lock.Mutex
	parent    *os.File
	directory *os.File
	owner     *os.File
	ops       intentOperations
	poisoned  error
	closed    bool
}

const intentDirectory = "ztunnel-required"

func OpenIntentStore(stateDir string) (*IntentStore, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("%w: state directory must be absolute", errRequiredUnsafe)
	}
	fd, err := unix.Open(stateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening required intent parent: %w", err)
	}
	parent := os.NewFile(uintptr(fd), stateDir)
	var parentStat unix.Stat_t
	if err = unix.Fstat(fd, &parentStat); err != nil {
		parent.Close()
		return nil, err
	}
	if parentStat.Uid != uint32(os.Geteuid()) || parentStat.Mode&0022 != 0 {
		parent.Close()
		return nil, fmt.Errorf("%w: parent ownership or write permissions", errRequiredUnsafe)
	}
	if err = unix.Mkdirat(fd, intentDirectory, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		parent.Close()
		return nil, fmt.Errorf("creating required intent directory: %w", err)
	}
	dirfd, err := unix.Openat(fd, intentDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		parent.Close()
		return nil, fmt.Errorf("opening required intent directory: %w", err)
	}
	directory := os.NewFile(uintptr(dirfd), intentDirectory)
	s := &IntentStore{parent: parent, directory: directory}
	cleanup := func() { directory.Close(); parent.Close() }
	if err = s.validateDirectory(); err != nil {
		cleanup()
		return nil, err
	}
	if err = parent.Sync(); err != nil {
		cleanup()
		return nil, fmt.Errorf("syncing required intent parent: %w", err)
	}
	ownerfd, err := unix.Openat(dirfd, ".owner", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("opening required intent owner: %w", err)
	}
	s.owner = os.NewFile(uintptr(ownerfd), ".owner")
	if err = validateIntentFile(s.owner); err == nil {
		err = unix.Flock(ownerfd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		s.owner.Close()
		cleanup()
		return nil, fmt.Errorf("locking required intent owner: %w", err)
	}
	s.ops = intentOperations{
		writeFile: func(f *os.File, data []byte) error {
			n, e := f.Write(data)
			if e == nil && n != len(data) {
				return io.ErrShortWrite
			}
			return e
		},
		syncFile: func(f *os.File) error { return f.Sync() },
		rename:   func(oldName, newName string) error { return unix.Renameat(dirfd, oldName, dirfd, newName) },
		syncDir:  directory.Sync,
	}
	return s, nil
}

func (s *IntentStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.owner.Close(), s.directory.Close(), s.parent.Close())
}

func (s *IntentStore) validateDirectory() error {
	var actual, named unix.Stat_t
	if err := unix.Fstat(int(s.directory.Fd()), &actual); err != nil {
		return err
	}
	if err := unix.Fstatat(int(s.parent.Fd()), intentDirectory, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if actual.Uid != uint32(os.Geteuid()) || actual.Mode&07777 != 0700 ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR || actual.Dev != named.Dev || actual.Ino != named.Ino {
		return fmt.Errorf("%w: directory ownership, permissions or incarnation changed", errRequiredUnsafe)
	}
	return nil
}

func (s *IntentStore) usableLocked() error {
	if s.closed {
		return errRequiredClosed
	}
	if s.poisoned != nil {
		return s.poisoned
	}
	if err := s.validateDirectory(); err != nil {
		s.poisoned = err
		return err
	}
	return nil
}

func validateRequiredIdentity(i RequiredIdentity) error {
	for _, v := range []string{i.NodeName, i.Namespace, i.NamespaceUID, i.PodName, i.PodUID, i.ServiceAccount, i.ContainerID, i.NetnsPath} {
		if v == "" || strings.TrimSpace(v) != v || len(v) > 4096 {
			return fmt.Errorf("%w: incomplete or malformed sandbox identity", errRequiredInvalid)
		}
	}
	if i.EndpointID == 0 || i.NetnsInode == 0 || i.NetnsCookie == 0 || !filepath.IsAbs(i.NetnsPath) {
		return fmt.Errorf("%w: invalid endpoint or network namespace", errRequiredInvalid)
	}
	return nil
}

func intentFilename(i RequiredIdentity) string {
	key, _ := json.Marshal([]any{i.ClusterID, i.NodeName, i.NamespaceUID, i.PodUID})
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:]) + ".json"
}

func validateIntentFile(f *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size > 64*1024 {
		return fmt.Errorf("%w: record must be a private, singly linked regular file", errRequiredUnsafe)
	}
	return nil
}

func (s *IntentStore) read(name string) (RequiredIntent, error) {
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return RequiredIntent{}, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err = validateIntentFile(f); err != nil {
		return RequiredIntent{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(f, 64*1024+1))
	decoder.DisallowUnknownFields()
	var value RequiredIntent
	if err = decoder.Decode(&value); err != nil {
		return RequiredIntent{}, err
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return RequiredIntent{}, fmt.Errorf("%w: trailing record data", errRequiredInvalid)
	}
	if value.SchemaVersion != 1 {
		return RequiredIntent{}, fmt.Errorf("%w: unsupported schema", errRequiredInvalid)
	}
	id, err := uuid.Parse(value.Incarnation)
	if err != nil || id == uuid.Nil {
		return RequiredIntent{}, fmt.Errorf("%w: invalid incarnation", errRequiredInvalid)
	}
	if err = validateRequiredIdentity(value.RequiredIdentity); err != nil {
		return RequiredIntent{}, err
	}
	if name != intentFilename(value.RequiredIdentity) {
		return RequiredIntent{}, fmt.Errorf("%w: filename disagrees with identity", errRequiredInvalid)
	}
	return value, nil
}

// PersistRequired succeeds only after file contents and the rename are durable.
// A failure after rename poisons this owner: an uncertain commit cannot ACK CNI.
// Repeated calls are idempotent only for the exact validated sandbox identity.
func (s *IntentStore) PersistRequired(identity RequiredIdentity) (RequiredIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return RequiredIntent{}, err
	}
	if err := validateRequiredIdentity(identity); err != nil {
		return RequiredIntent{}, err
	}
	name := intentFilename(identity)
	if old, err := s.read(name); err == nil {
		if old.RequiredIdentity != identity {
			return RequiredIntent{}, errRequiredConflict
		}
		return old, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return RequiredIntent{}, fmt.Errorf("reading required intent: %w", err)
	}
	value := RequiredIntent{SchemaVersion: 1, RequiredIdentity: identity, Incarnation: uuid.NewString()}
	data, err := json.Marshal(value)
	if err != nil {
		return RequiredIntent{}, err
	}
	temp := ".intent-" + uuid.NewString()
	fd, err := unix.Openat(int(s.directory.Fd()), temp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return RequiredIntent{}, fmt.Errorf("creating required intent temporary file: %w", err)
	}
	f := os.NewFile(uintptr(fd), temp)
	defer unix.Unlinkat(int(s.directory.Fd()), temp, 0)
	if err = s.ops.writeFile(f, data); err == nil {
		err = s.ops.syncFile(f)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return RequiredIntent{}, fmt.Errorf("writing required intent: %w", err)
	}
	if err = s.ops.rename(temp, name); err != nil {
		return RequiredIntent{}, fmt.Errorf("renaming required intent: %w", err)
	}
	if err = s.ops.syncDir(); err != nil {
		s.poisoned = fmt.Errorf("%w: %w", errRequiredIndeterminate, err)
		return RequiredIntent{}, s.poisoned
	}
	return value, nil
}

// List returns intent only. The caller must not restore ACKs or admit packets
// from these records; live identity/sandbox verification and fresh evidence are
// mandatory. Malformed records block the whole candidate recovery snapshot.
func (s *IntentStore) List() ([]RequiredIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(s.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), intentDirectory)
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	records := make([]RequiredIntent, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".owner" || strings.HasPrefix(name, ".intent-") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("%w: unknown record file", errRequiredInvalid)
		}
		record, err := s.read(name)
		if err != nil {
			return nil, fmt.Errorf("loading required intent snapshot: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}
