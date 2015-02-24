// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Julien Vehent julien@linuxwall.info
package pgptoken

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"time"
)

const (
	TokenVersion = 1
)

// Identity contains information about the signer of a pgptoken.
// The fields Id, Name and Email are set by the signer and should
// not be trusted for authentication. Instead, the Fingerprint should
// be used to uniquely identify a user against an identity database
// (ldap, ...).
type Identity struct {
	Id          string // by convention, has the form "Full Name (comment) <email@example.com>"
	Name        string // name as defined in the pgp public key
	Email       string // email as defined in the pgp public key
	Fingerprint string // 20 bytes / 160 bits hexadecimal fingerprint
}

// a Tokenizer signs and verifies tokens. It must be initialized with
// a PGP Keyring, and optional parameters such as a token validity window.
type Tokenizer struct {
	KeyringPath    string        // file path to the pubring or secring
	Keyring        io.ReadSeeker // io reader on the keyring that can be rewinded
	ValidityWindow time.Duration // accept tokens emitted during: (now - validity) < now < (now + validity)
}

// makeKeyring retrieves GPG keys of active investigators from the database and makes
// a GPG keyring out of it
func makeKeyring() (keyring io.ReadSeeker, err error) {
	keys, err := ctx.DB.ActiveInvestigatorsKeys()
	if err != nil {
		panic(err)
	}
	keyring, keycount, err := pgp.ArmoredKeysToKeyring(keys)
	if err != nil {
		panic(err)
	}
	ctx.Channels.Log <- mig.Log{Desc: fmt.Sprintf("loaded %d keys from active investigators", keycount)}.Debug()
	return
}

// getKeyring copy an io.Reader from the master keyring. If the keyring hasn't been refreshed
// in a while, it also gets a fresh copy from the database
func getKeyring() (kr io.Reader, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("getKeyring() -> %v", e)
		}
		ctx.Channels.Log <- mig.Log{Desc: "leaving getKeyring()"}.Debug()
	}()
	// make sure we don't competing Seek calls or interfering copies by setting a mutex
	ctx.Keyring.Mutex.Lock()
	defer ctx.Keyring.Mutex.Unlock()
	// refresh keyring from DB if older than 5 minutes
	if ctx.Keyring.UpdateTime.Before(time.Now().Add(-5 * time.Minute)) {
		ctx.Keyring.Reader, err = makeKeyring()
		if err != nil {
			panic(err)
		}
		ctx.Keyring.UpdateTime = time.Now()
	} else {
		// rewind the master keyring
		_, err = ctx.Keyring.Reader.Seek(0, 0)
		if err != nil {
			panic(err)
		}
	}
	// copy the master keyring over to a local one
	buf, err := ioutil.ReadAll(ctx.Keyring.Reader)
	if err != nil {
		panic(err)
	}
	kr = bytes.NewBuffer(buf)
	return
}
