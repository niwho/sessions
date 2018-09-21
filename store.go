// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"encoding/base32"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/niwho/chains"
	"github.com/niwho/logs"
)

// Store is an interface for custom session stores.
//
// See CookieStore and FilesystemStore for examples.
type Store interface {
	// Get should return a cached session.
	Get(r *http.Request, name string) (*Session, error)

	// New should create and return a new session.
	//
	// Note that New should never return a nil session, even in the case of
	// an error if using the Registry infrastructure to cache the session.
	New(r *http.Request, name string) (*Session, error)

	// Save should persist session to the underlying store implementation.
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// CookieStore ----------------------------------------------------------------

// NewCookieStore returns a new CookieStore.
//
// Keys are defined in pairs to allow key rotation, but the common case is
// to set a single authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for
// encryption. The encryption key can be set to nil or omitted in the last
// pair, but the authentication key is required in all pairs.
//
// It is recommended to use an authentication key with 32 or 64 bytes.
// The encryption key, if set, must be either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256 modes.
func NewCookieStore(keyPairs ...[]byte) *CookieStore {
	cs := &CookieStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
	}

	cs.MaxAge(cs.Options.MaxAge)
	return cs
}

// CookieStore stores sessions using secure cookies.
type CookieStore struct {
	Codecs  []securecookie.Codec
	Options *Options // default configuration
}

// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (s *CookieStore) Get(r *http.Request, name string) (*Session, error) {
	return GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
func (s *CookieStore) New(r *http.Request, name string) (*Session, error) {
	session := NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.Values,
			s.Codecs...)
		if err == nil {
			session.IsNew = false
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *CookieStore) Save(r *http.Request, w http.ResponseWriter,
	session *Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *CookieStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// FilesystemStore ------------------------------------------------------------

var fileMutex sync.RWMutex

// NewFilesystemStore returns a new FilesystemStore.
//
// The path argument is the directory where sessions will be saved. If empty
// it will use os.TempDir().
//
// See NewCookieStore() for a description of the other parameters.
func NewFilesystemStore(path string, keyPairs ...[]byte) *FilesystemStore {
	if path == "" {
		path = os.TempDir()
	}
	fs := &FilesystemStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		path: path,
	}

	fs.MaxAge(fs.Options.MaxAge)
	return fs
}

// FilesystemStore stores sessions in the filesystem.
//
// It also serves as a reference for custom stores.
//
// This store is still experimental and not well tested. Feedback is welcome.
type FilesystemStore struct {
	Codecs  []securecookie.Codec
	Options *Options // default configuration
	path    string
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new FilesystemStore is 4096.
func (s *FilesystemStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *FilesystemStore) Get(r *http.Request, name string) (*Session, error) {
	return GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *FilesystemStore) New(r *http.Request, name string) (*Session, error) {
	session := NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
//
// If the Options.MaxAge of the session is <= 0 then the session file will be
// deleted from the store path. With this process it enforces the properly
// session cookie handling so no need to trust in the cookie management in the
// web browser.
func (s *FilesystemStore) Save(r *http.Request, w http.ResponseWriter,
	session *Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session); err != nil {
			return err
		}
		http.SetCookie(w, NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		// Because the ID is used in the filename, encode it to
		// use alphanumeric characters only.
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
	}
	if err := s.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *FilesystemStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// save writes encoded session.Values to a file.
func (s *FilesystemStore) save(session *Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}
	filename := filepath.Join(s.path, "session_"+session.ID)
	fileMutex.Lock()
	defer fileMutex.Unlock()
	return ioutil.WriteFile(filename, []byte(encoded), 0600)
}

// load reads a file and decodes its content into session.Values.
func (s *FilesystemStore) load(session *Session) error {
	filename := filepath.Join(s.path, "session_"+session.ID)
	fileMutex.RLock()
	defer fileMutex.RUnlock()
	fdata, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if err = securecookie.DecodeMulti(session.Name(), string(fdata),
		&session.Values, s.Codecs...); err != nil {
		return err
	}
	return nil
}

// delete session file
func (s *FilesystemStore) erase(session *Session) error {
	filename := filepath.Join(s.path, "session_"+session.ID)

	fileMutex.RLock()
	defer fileMutex.RUnlock()

	err := os.Remove(filename)
	return err
}

// MultiStore ------------------------------------------------------------

// NewMultiStore returns a new MultiStore.
//
// The path argument is the directory where sessions will be saved. If empty
// it will use os.TempDir().
//
// See NewCookieStore() for a description of the other parameters.
func NewMultiStore(loaders *chains.DataLoaderManager, keyPairs ...[]byte) *MultiStore {
	fs := &MultiStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		loaders: loaders,
	}

	fs.MaxAge(fs.Options.MaxAge)
	return fs
}

// MultiStore stores sessions in the filesystem.
//
// It also serves as a reference for custom stores.
//
// This store is still experimental and not well tested. Feedback is welcome.
type MultiStore struct {
	Codecs  []securecookie.Codec
	Options *Options // default configuration

	loaders *chains.DataLoaderManager
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new MultiStore is 4096.
func (s *MultiStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *MultiStore) Get(r *http.Request, name string) (*Session, error) {
	return GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *MultiStore) New(r *http.Request, name string) (*Session, error) {
	session := NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	// 不支持客户端session，所以不加密
	if c, errCookie := r.Cookie(name); errCookie == nil {
		//err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		session.ID = c.Value
		err = s.load(session)
		if err == nil {
			session.IsNew = false
		}
	}
	return session, err
}

// Save adds a single session to the response.
//
// If the Options.MaxAge of the session is <= 0 then the session file will be
// deleted from the store path. With this process it enforces the properly
// session cookie handling so no need to trust in the cookie management in the
// web browser.
func (s *MultiStore) Save(r *http.Request, w http.ResponseWriter,
	session *Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session); err != nil {
			return err
		}
		http.SetCookie(w, NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		// Because the ID is used in the filename, encode it to
		// use alphanumeric characters only.
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
	}
	if err := s.save(session); err != nil {
		return err
	}
	// session.ID 不加密
	http.SetCookie(w, NewCookie(session.Name(), session.ID, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *MultiStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// save writes encoded session.Values to a file.
func (s *MultiStore) save(session *Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}
	s.loaders.Set(session.ID, encoded)
	return nil
}

// load reads a file and decodes its content into session.Values.
func (s *MultiStore) load(session *Session) error {
	dat := s.loaders.Get(session.ID)
	if data, ok := dat.(string); ok {
		if err := securecookie.DecodeMulti(session.Name(), data,
			&session.Values, s.Codecs...); err != nil {
			return err
		}
	} else {
		logs.Log(logs.F{"err": "string convert failed", "origin_data": dat}).Error("MultiStore:load")
		return errors.New("string convert failed")
	}
	return nil
}

// delete session file
func (s *MultiStore) erase(session *Session) error {
	s.loaders.Del(session.ID)
	return nil
}
