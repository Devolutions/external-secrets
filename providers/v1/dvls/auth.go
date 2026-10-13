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

// Package dvls implements the external-secrets provider for Devolutions Server (DVLS).
package dvls

import (
	"context"
	"fmt"
	"sync"

	"github.com/Devolutions/go-dvls"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

type realVaultClient struct {
	vaults *dvls.Vaults
	mu     *sync.Mutex
}

func (r *realVaultClient) GetByName(ctx context.Context, name string) (dvls.Vault, error) {
	if r.mu != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	return r.vaults.GetByNameWithContext(ctx, name)
}

// NewDVLSClient creates a new authenticated DVLS client and resolves the vault.
func NewDVLSClient(ctx context.Context, kube kclient.Client, storeKind, namespace string, provider *esv1.DVLSProvider) (credentialClient, string, error) {
	if provider == nil {
		return nil, "", fmt.Errorf("missing provider configuration")
	}

	appID, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &provider.Auth.SecretRef.AppID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get appId: %w", err)
	}

	appSecret, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &provider.Auth.SecretRef.AppSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get appSecret: %w", err)
	}

	shared, err := getSharedClient(provider.ServerURL, appID, appSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create DVLS client: %w", err)
	}
	client := shared.client

	credClient := &realCredentialClient{cred: client.Entries.Credential, mu: &shared.mu}

	// When vault is empty, the provider operates in legacy mode where
	// the vault ID is expected in the secret key (<vault-id>/<entry-id>).
	if provider.Vault == "" {
		return credClient, "", nil
	}

	vaultCl := &realVaultClient{vaults: client.Vaults, mu: &shared.mu}
	vaultID, err := resolveVaultRef(ctx, provider.Vault, vaultCl)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve vault: %w", err)
	}

	return credClient, vaultID, nil
}
