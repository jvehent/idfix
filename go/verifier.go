// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]
package pgptoken

import (
	"fmt"
	"strings"
	"time"
)

const (
	E_WrongVersion = "unexpected token version, expected version 1"
	E_TokenFormat  = "invalid token format"
	E_TimeFormat   = "invalid timestamp format"
	E_TimeValidity = "token timestamp is not within acceptable time window"
)

// Verify verifies the signature of a pgptoken. It returns the identity of the signer and
// an error if the verification fails
func (t Tokenizer) Verify(token string) (ident Identity, err error) {
	parts := strings.Split(token, ";")
	if len(parts) != 4 {
		return ident, fmt.Errorf(E_TokenFormat)
	}
	// verify token version
	tv := parts[0]
	if tv != fmt.Sprintf("%d", TokenVersion) {
		return ident, fmt.Errorf(E_WrongVersion)
	}
	// verify that token timestamp is recent enough
	tstr := parts[1]
	ts, err := time.Parse("2006-01-02T15:04:05Z", tstr)
	if err != nil {
		return ident, fmt.Errorf(E_TimeFormat)
	}
	early := time.Now().Add(-t.ValidityWindow)
	late := time.Now().Add(t.ValidityWindow)
	if ts.Before(early) || ts.After(late) {
		return ident, fmt.Errorf(E_TimeValidity)
	}
	nonce := parts[2]
	sig := parts[3]
	keyring, err := getKeyring()
	if err != nil {
		return
	}

	fp, err := pgp.GetFingerprintFromSignature(tv+";"+tstr+";"+nonce+"\n", sig, keyring)
	if err != nil {
		panic(err)
	}
	if fp == "" {
		panic("token verification failed")
	}
	inv, err = ctx.DB.InvestigatorByFingerprint(fp)
	if err != nil {
		panic(err)
	}
	return
}
