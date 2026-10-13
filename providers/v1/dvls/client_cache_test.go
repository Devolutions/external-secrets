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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFakeDVLS(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	logins := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/login":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"tokenId":"token"}`))
		case "/api/is-logged":
			_, _ = w.Write([]byte(`true`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, logins
}

func resetClientCache(t *testing.T) {
	t.Helper()
	clientCache.Lock()
	clientCache.clients = map[string]*sharedClient{}
	clientCache.Unlock()
}

func TestGetSharedClient_ReusesLogin(t *testing.T) {
	resetClientCache(t)
	srv, logins := newFakeDVLS(t)

	first, err := getSharedClient(srv.URL, "app", "secret")
	require.NoError(t, err)
	for range 5 {
		c, err := getSharedClient(srv.URL, "app", "secret")
		require.NoError(t, err)
		assert.Same(t, first, c)
	}

	assert.Equal(t, int32(1), logins.Load())
}

func TestGetSharedClient_NewLoginWhenCredentialsChange(t *testing.T) {
	resetClientCache(t)
	srv, logins := newFakeDVLS(t)

	a, err := getSharedClient(srv.URL, "app", "secret")
	require.NoError(t, err)
	b, err := getSharedClient(srv.URL, "app", "rotated-secret")
	require.NoError(t, err)

	assert.NotSame(t, a, b)
	assert.Equal(t, int32(2), logins.Load())
}

func TestGetSharedClient_FailedLoginIsNotCached(t *testing.T) {
	resetClientCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, err := getSharedClient(srv.URL, "app", "secret")
	require.Error(t, err)

	clientCache.Lock()
	defer clientCache.Unlock()
	assert.Empty(t, clientCache.clients)
}

func TestGetSharedClient_ConcurrentCallersShareOneLogin(t *testing.T) {
	resetClientCache(t)
	srv, logins := newFakeDVLS(t)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			c, err := getSharedClient(srv.URL, "app", "secret")
			assert.NoError(t, err)
			cred := &realCredentialClient{cred: c.client.Entries.Credential, mu: &c.mu}
			_, _ = cred.GetByID(t.Context(), "vault", "entry")
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), logins.Load())
}
