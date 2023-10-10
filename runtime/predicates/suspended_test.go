/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package predicates

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	pkgmetav1 "github.com/fluxcd/pkg/apis/meta"
)

func TestSuspendedPredicateUpdate(t *testing.T) {
	getConfigMapWithAnnotations := func(annotations map[string]string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: annotations,
			},
		}
	}

	tests := []struct {
		name      string
		oldObject client.Object
		newObject client.Object
		want      bool
	}{
		{
			name:      "no new object",
			oldObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			newObject: nil,
			want:      false,
		},
		{
			name:      "no old object",
			oldObject: nil,
			newObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			want:      false,
		},
		{
			name:      "suspended annotation in new obj",
			oldObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			newObject: getConfigMapWithAnnotations(map[string]string{
				"foo":                         "bar",
				pkgmetav1.SuspendedAnnotation: "true",
			}),
			want: false,
		},
		{
			name: "suspended annotation in old obj",
			oldObject: getConfigMapWithAnnotations(map[string]string{
				"foo":                         "bar",
				pkgmetav1.SuspendedAnnotation: "true",
			}),
			newObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			want:      true,
		},
		{
			name:      "no suspended annotations in either obj",
			oldObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			newObject: getConfigMapWithAnnotations(map[string]string{"foo": "bar"}),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			e := event.UpdateEvent{
				ObjectOld: tt.oldObject,
				ObjectNew: tt.newObject,
			}
			sus := SuspendedPredicate{}
			g.Expect(sus.Update(e)).To(Equal(tt.want))
		})
	}
}
