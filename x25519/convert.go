// Copyright © 2017-2018 The IPFN Developers. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package x25519

import (
	"crypto/sha512"

	"github.com/agl/ed25519/extra25519"
)

// PublicFromEd25519 - Converts ed25519 to X25519 public key.
func PublicFromEd25519(publicKey *[32]byte) (x25519Public [32]byte, ok bool) {
	ok = extra25519.PublicKeyToCurve25519(&x25519Public, publicKey)
	return
}

// PrivateFromEd25519 - Converts ed25519 to X25519 private key.
func PrivateFromEd25519(privateKey *[32]byte) (x25519Private [32]byte) {
	h := sha512.New()
	h.Write(privateKey[:])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	copy(x25519Private[:], digest)
	return
}
