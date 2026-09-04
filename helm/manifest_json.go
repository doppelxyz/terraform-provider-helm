// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package helm

import (
	"crypto/sha3"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"helm.sh/helm/v3/pkg/releaseutil"
)

type resourceMeta struct {
	metav1.TypeMeta
	Metadata metav1.ObjectMeta
}

func convertYAMLManifestToJSON(manifest string) (string, error) {
	m := map[string]json.RawMessage{}

	resources := releaseutil.SplitManifests(manifest)
	for _, resource := range resources {
		jsonbytes, err := yaml.YAMLToJSON([]byte(resource))
		if err != nil {
			return "", fmt.Errorf("could not convert manifest to JSON: %v", err)
		}

		resourceMeta := resourceMeta{}
		err = yaml.Unmarshal([]byte(resource), &resourceMeta)
		if err != nil {
			return "", err
		}

		gvk := resourceMeta.GetObjectKind().GroupVersionKind()
		key := fmt.Sprintf("%s/%s/%s", strings.ToLower(gvk.GroupKind().String()),
			resourceMeta.APIVersion,
			resourceMeta.Metadata.Name)

		if namespace := resourceMeta.Metadata.Namespace; namespace != "" {
			key = fmt.Sprintf("%s/%s", namespace, key)
		}

		if gvk.Kind == "Secret" {
			secret := corev1.Secret{}
			err = yaml.Unmarshal([]byte(resource), &secret)
			if err != nil {
				return "", err
			}

			for k, v := range secret.Data {
				h := hashSensitiveValue(string(v))
				secret.Data[k] = []byte(h)
			}

			jsonbytes, err = json.Marshal(secret)
			if err != nil {
				return "", err
			}
		}

		m[key] = jsonbytes
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func hashSensitiveValue(v string) string {
	hash := sha3.SumSHAKE256([]byte(v), 8)
	return fmt.Sprintf("(sensitive value %x)", hash)
}

// redactSensitiveValues replaces every occurrence of a set_sensitive value in
// text with a stable hash, so a manifest stored in state or plan output never
// contains a value the caller marked sensitive.
//
// Empty strings are skipped: strings.ReplaceAll(text, "", marker) matches
// every position and would corrupt the manifest. sensitiveSetValues already
// filters these out; this is a second guard.
func redactSensitiveValues(text string, sensitiveValues []string) string {
	masked := text

	for _, value := range sensitiveValues {
		if value == "" {
			continue
		}

		// text is always JSON (produced by json.Marshal), so a value with a
		// character JSON escapes never appears as raw bytes. Search for the
		// escaped form instead (quotes, backslashes, newlines, and so on).
		escaped, ok := jsonEscapedForm(value)
		if !ok || escaped == "" {
			continue
		}
		masked = strings.ReplaceAll(masked, escaped, hashSensitiveValue(value))
	}

	return masked
}

// jsonEscapedForm returns value as it appears inside a JSON string field —
// json.Marshal's quoted encoding with the surrounding quotes stripped.
func jsonEscapedForm(value string) (string, bool) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return "", false
	}
	return string(b[1 : len(b)-1]), true
}

func redactSecretData(secret *corev1.Secret) {
	for k, v := range secret.Data {
		h := hashSensitiveValue(string(v))
		secret.Data[k] = []byte(h)
	}
}
