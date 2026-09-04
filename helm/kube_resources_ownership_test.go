// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestSetDryRunOwnershipMetadata(t *testing.T) {
	t.Run("object with no labels at all", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "app"},
		}}

		require.NoError(t, setDryRunOwnershipMetadata(obj))

		assert.Equal(t, "Helm", obj.GetLabels()["app.kubernetes.io/managed-by"])
	})

	t.Run("existing labels are preserved, not replaced", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{
				"name":   "app",
				"labels": map[string]any{"app.kubernetes.io/name": "litellm"},
			},
		}}

		require.NoError(t, setDryRunOwnershipMetadata(obj))

		assert.Equal(t, "litellm", obj.GetLabels()["app.kubernetes.io/name"])
		assert.Equal(t, "Helm", obj.GetLabels()["app.kubernetes.io/managed-by"])
	})

	t.Run("a conflicting prior value is force-overwritten", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{
				"name": "app",
				"labels": map[string]any{
					"app.kubernetes.io/managed-by": "something-else",
				},
			},
		}}

		require.NoError(t, setDryRunOwnershipMetadata(obj))

		assert.Equal(t, "Helm", obj.GetLabels()["app.kubernetes.io/managed-by"])
	})

	t.Run("Secret kind is unaffected by the function itself", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": "app-secret"},
		}}

		require.NoError(t, setDryRunOwnershipMetadata(obj))

		assert.Equal(t, "Helm", obj.GetLabels()["app.kubernetes.io/managed-by"])
	})
}
