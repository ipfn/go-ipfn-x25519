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
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestPublicFromEd25519(t *testing.T) {
	seed := sha256.Sum256([]byte("test1")) // 1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014
	edPublicKey, edPrivateKey := ed25519KeyFromSeed(seed[:])
	curvePrivateKey := PrivateFromEd25519(&edPrivateKey)
	curvePublicKey, ok := PublicFromEd25519(&edPublicKey)
	assert.Equal(t, true, ok)
	assert.Equal(t, Public(&curvePrivateKey), curvePublicKey)
}

func ed25519KeyFromSeed(seed []byte) (publicKey, privateKey [32]byte) {
	pk := ed25519.NewKeyFromSeed(seed)
	copy(privateKey[:], pk[:32])
	copy(publicKey[:], pk[32:])
	return
}
