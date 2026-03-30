package pxc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/percona/percona-xtradb-cluster-operator/pkg/apis"
	pxcv1 "github.com/percona/percona-xtradb-cluster-operator/pkg/apis/pxc/v1"
	"github.com/percona/percona-xtradb-cluster-operator/pkg/naming"
)

func TestReconcilePersistentVolumesVolumeExternalAutoscaling(t *testing.T) {
	const (
		namespace      = "test-ns"
		clusterName    = "test-cluster"
		configuredSize = "1Gi"
		requestedSize  = "2Gi"
	)

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, apis.AddToScheme(scheme))

	labels := naming.LabelsPXC(&pxcv1.PerconaXtraDBCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName,
			Namespace: namespace,
		},
	})

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName + "-pxc",
			Namespace: namespace,
		},
		Spec: appsv1.StatefulSetSpec{
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "datadir",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse(configuredSize),
							},
						},
					},
				},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-pxc-0",
			Namespace: namespace,
			Labels:    labels,
		},
	}

	cr := &pxcv1.PerconaXtraDBCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName,
			Namespace: namespace,
		},
		Spec: pxcv1.PerconaXtraDBClusterSpec{
			PXC: &pxcv1.PXCSpec{
				PodSpec: &pxcv1.PodSpec{
					Size: 1,
					VolumeSpec: &pxcv1.VolumeSpec{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimSpec{
							Resources: corev1.VolumeResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceStorage: resource.MustParse(requestedSize),
								},
							},
						},
					},
				},
			},
		},
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "datadir-test-cluster-pxc-0",
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(configuredSize),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse(configuredSize),
			},
		},
	}

	tests := map[string]struct {
		volumeExternalAutoscaling bool
		volumeExpansionEnabled    bool
		expectRequestedSize       string
		expectPVCSize             string
		expectResizeAnnotation    bool
	}{
		"external autoscaling enabled, volume expansion enabled": {
			volumeExternalAutoscaling: true,
			volumeExpansionEnabled:    true,
			expectRequestedSize:       requestedSize,
			expectPVCSize:             configuredSize,
			expectResizeAnnotation:    false,
		},
		"external autoscaling enabled, volume expansion disabled": {
			volumeExternalAutoscaling: true,
			volumeExpansionEnabled:    false,
			expectRequestedSize:       requestedSize,
			expectPVCSize:             configuredSize,
			expectResizeAnnotation:    false,
		},
		"external autoscaling disabled, volume expansion enabled": {
			volumeExternalAutoscaling: false,
			volumeExpansionEnabled:    true,
			expectRequestedSize:       requestedSize,
			expectPVCSize:             requestedSize,
			expectResizeAnnotation:    true,
		},
		"external autoscaling disabled, volume expansion disabled": {
			volumeExternalAutoscaling: false,
			volumeExpansionEnabled:    false,
			expectRequestedSize:       configuredSize,
			expectPVCSize:             configuredSize,
			expectResizeAnnotation:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			cr := cr.DeepCopy()
			pvc := pvc.DeepCopy()

			cr.Spec.VolumeExternalAutoscaling = tt.volumeExternalAutoscaling
			cr.Spec.VolumeExpansionEnabled = tt.volumeExpansionEnabled

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cr, sts, pvc, pod).
				Build()

			r := &ReconcilePerconaXtraDBCluster{
				client:  cl,
				scheme:  scheme,
				crons:   NewCronRegistry(),
				lockers: newLockStore(),
			}

			err := r.reconcilePersistentVolumes(ctx, cr)
			require.NoError(t, err)

			gotCR := new(pxcv1.PerconaXtraDBCluster)
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(cr), gotCR))
			assert.Equal(t, tt.expectResizeAnnotation, gotCR.PVCResizeInProgress())

			requestedSize := cr.Spec.PXC.VolumeSpec.PersistentVolumeClaim.Resources.Requests[corev1.ResourceStorage]
			assert.Zero(
				t,
				requestedSize.Cmp(resource.MustParse(tt.expectRequestedSize)),
			)

			gotPVC := new(corev1.PersistentVolumeClaim)
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(pvc), gotPVC))
			pvcSize := gotPVC.Spec.Resources.Requests[corev1.ResourceStorage]
			assert.Zero(
				t,
				pvcSize.Cmp(resource.MustParse(tt.expectPVCSize)),
			)
		})
	}
}
