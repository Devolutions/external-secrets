/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dvls

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/Devolutions/go-dvls"
)

// newDVLSClient is the go-dvls constructor, which performs a login. It is a
// variable so tests can count logins without a DVLS server.
var newDVLSClient = dvls.NewClient

// sharedClient is a go-dvls client reused across reconciliations. go-dvls
// renews its token on demand but does not guard it, so calls are serialized.
type sharedClient struct {
	mu     sync.Mutex
	client *dvls.Client
}

var clientCache = struct {
	sync.Mutex
	clients map[string]*sharedClient
}{clients: map[string]*sharedClient{}}

func clientCacheKey(serverURL, appID, appSecret string) string {
	sum := sha256.Sum256([]byte(serverURL + "\x00" + appID + "\x00" + appSecret))
	return hex.EncodeToString(sum[:])
}

// getSharedClient returns the cached client for these credentials, logging in
// only when none exists. A rotated secret yields a new key and a fresh login.
func getSharedClient(serverURL, appID, appSecret string) (*sharedClient, error) {
	key := clientCacheKey(serverURL, appID, appSecret)

	clientCache.Lock()
	defer clientCache.Unlock()

	if c, ok := clientCache.clients[key]; ok {
		return c, nil
	}

	client, err := newDVLSClient(appID, appSecret, serverURL)
	if err != nil {
		return nil, err
	}

	c := &sharedClient{client: &client}
	clientCache.clients[key] = c
	return c, nil
}
