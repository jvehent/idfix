// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Julien Vehent julien@linuxwall.info
package tokid

import (
	"fmt"
	"time"
)

const ()

// Generate makes a token string composed of the token version, a timestamp
// and a 128 bits random number, and signs it using the private key defined
// in the tokenizer. It returns the token string and an error.
func (t Tokenizer) Generate() (token string, err error) {
	nonce := time.Now().UnixNano()
	nonce ^= float64(rand.Int63())
	str := fmt.Sprintf("%d;%s;%.0f%.0f",
		TokenVersion,
		time.Now().UTC().Format(time.RFC3339),
		nonce,
		float64(rand.Int63()),
	)
	secringFile, err := os.Open(cli.Conf.GPG.Home + "/secring.gpg")
	if err != nil {
		panic(err)
	}
	defer secringFile.Close()
	sig, err := pgp.Sign(str+"\n", cli.Conf.GPG.KeyID, secringFile)
	if err != nil {
		panic(err)
	}
	token = str + ";" + sig
	return
}
