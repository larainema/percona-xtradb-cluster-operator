package pxc

import (
	"context"
	"fmt"
	"time"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	api "github.com/percona/percona-xtradb-cluster-operator/pkg/apis/pxc/v1"
	"github.com/percona/percona-xtradb-cluster-operator/pkg/k8s"
	"github.com/percona/percona-xtradb-cluster-operator/pkg/naming"
	"github.com/percona/percona-xtradb-cluster-operator/pkg/pxctls"
)

func (r *ReconcilePerconaXtraDBCluster) reconcileSSL(ctx context.Context, cr *api.PerconaXtraDBCluster) error {
	if err := r.reconcileTLSToggle(ctx, cr); err != nil {
		return errors.Wrap(err, "reconcile tls toggle")
	}

	if !cr.TLSEnabled() {
		return nil
	}

	secretObj := corev1.Secret{}
	secretInternalObj := corev1.Secret{}
	errSecret := r.client.Get(ctx,
		types.NamespacedName{
			Namespace: cr.Namespace,
			Name:      cr.Spec.PXC.SSLSecretName,
		},
		&secretObj,
	)
	errInternalSecret := r.client.Get(ctx,
		types.NamespacedName{
			Namespace: cr.Namespace,
			Name:      cr.Spec.PXC.SSLInternalSecretName,
		},
		&secretInternalObj,
	)
	if errSecret == nil && errInternalSecret == nil {
		// reconcile cert-manager Certificate specs on operator upgrade
		if err := r.reconcileCertManagerCertificateSpecs(ctx, cr); err != nil {
			if cr.Spec.TLS != nil && cr.Spec.TLS.IssuerConf != nil {
				return fmt.Errorf("reconcile cert-manager certificates: %w", err)
			}
			log := logf.FromContext(ctx)
			log.Info("Failed to reconcile cert-manager certificates, skipping (certs may be manually managed)", "error", err)
		}
		return nil
	} else if errSecret != nil && !k8serr.IsNotFound(errSecret) {
		return fmt.Errorf("get secret: %v", errSecret)
	} else if errInternalSecret != nil && !k8serr.IsNotFound(errInternalSecret) {
		return fmt.Errorf("get internal secret: %v", errInternalSecret)
	}
	// don't create secret ssl-internal if secret ssl is not created by operator
	if errSecret == nil && !metav1.IsControlledBy(&secretObj, cr) {
		return nil
	}
	err := r.createSSLByCertManager(ctx, cr)
	if err != nil {
		if cr.Spec.TLS != nil && cr.Spec.TLS.IssuerConf != nil {
			return fmt.Errorf("create ssl with cert manager %w", err)
		}
		err = r.createSSLManualy(ctx, cr)
		if err != nil {
			return fmt.Errorf("create ssl internally: %v", err)
		}
	}
	return nil
}

func (r *ReconcilePerconaXtraDBCluster) createSSLByCertManager(ctx context.Context, cr *api.PerconaXtraDBCluster) error {
	cfg := resolveTLSCertConfig(cr)

	if cr.Spec.TLS == nil || cr.Spec.TLS.IssuerConf == nil {
		if err := r.createIssuer(ctx, cr, cfg.caIssuerName, ""); err != nil {
			return err
		}

		caCert := buildCACertificate(cr, cfg)
		if err := r.createOrUpdateCertificate(ctx, caCert); err != nil {
			return fmt.Errorf("create or update CA certificate: %w", err)
		}

		if err := r.waitForCerts(ctx, cr.Namespace, caCert.Spec.SecretName); err != nil {
			return err
		}

		if err := r.createIssuer(ctx, cr, cfg.issuerName, caCert.Spec.SecretName); err != nil {
			return err
		}
	}

	kubeCert := buildSSLCertificate(cr, cfg)
	if err := r.createOrUpdateCertificate(ctx, kubeCert); err != nil {
		return fmt.Errorf("create or update certificate: %w", err)
	}

	if cr.Spec.PXC.SSLSecretName == cr.Spec.PXC.SSLInternalSecretName {
		return r.waitForCerts(ctx, cr.Namespace, cr.Spec.PXC.SSLSecretName)
	}

	kubeCertInternal := buildSSLInternalCertificate(cr, cfg)
	if err := r.createOrUpdateCertificate(ctx, kubeCertInternal); err != nil {
		return fmt.Errorf("create or update internal certificate: %w", err)
	}

	return r.waitForCerts(ctx, cr.Namespace, cr.Spec.PXC.SSLSecretName, cr.Spec.PXC.SSLInternalSecretName)
}

func (r *ReconcilePerconaXtraDBCluster) waitForCerts(ctx context.Context, namespace string, secretsList ...string) error {
	ticker := time.NewTicker(3 * time.Second)
	timeoutTimer := time.NewTimer(30 * time.Second)
	defer timeoutTimer.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			return errors.Errorf("timeout: can't get tls certificates from certmanager, %s", secretsList)
		case <-ticker.C:
			sucessCount := 0
			for _, secretName := range secretsList {
				secret := &corev1.Secret{}
				err := r.client.Get(ctx, types.NamespacedName{
					Name:      secretName,
					Namespace: namespace,
				}, secret)
				if err != nil && !k8serr.IsNotFound(err) {
					return err
				} else if err == nil {
					sucessCount++
				}
			}
			if sucessCount == len(secretsList) {
				return nil
			}
		}
	}
}

func (r *ReconcilePerconaXtraDBCluster) createIssuer(ctx context.Context, cr *api.PerconaXtraDBCluster, issuer string, caCertSecret string) error {
	spec := cm.IssuerSpec{}

	if caCertSecret == "" {
		spec = cm.IssuerSpec{
			IssuerConfig: cm.IssuerConfig{
				SelfSigned: &cm.SelfSignedIssuer{},
			},
		}
	} else {
		spec = cm.IssuerSpec{
			IssuerConfig: cm.IssuerConfig{
				CA: &cm.CAIssuer{SecretName: caCertSecret},
			},
		}
	}

	var ls map[string]string
	if cr.CompareVersionWith("1.16.0") >= 0 {
		ls = naming.LabelsCluster(cr)
	}
	err := r.client.Create(ctx, &cm.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuer,
			Namespace: cr.Namespace,
			Labels:    ls,
		},
		Spec: spec,
	})
	if err != nil && !k8serr.IsAlreadyExists(err) {
		return fmt.Errorf("create issuer: %v", err)
	}
	return nil
}

func (r *ReconcilePerconaXtraDBCluster) createSSLManualy(ctx context.Context, cr *api.PerconaXtraDBCluster) error {
	data := make(map[string][]byte)
	proxyHosts := []string{
		cr.Name + "-pxc",
		cr.Name + "-proxysql",
		"*." + cr.Name + "-pxc",
		"*." + cr.Name + "-proxysql",
	}
	if cr.Spec.TLS != nil && len(cr.Spec.TLS.SANs) > 0 {
		proxyHosts = append(proxyHosts, cr.Spec.TLS.SANs...)
	}
	caCert, tlsCert, key, err := pxctls.Issue(proxyHosts, cr.CompareVersionWith("1.19.0") >= 0, cr.CompareVersionWith("1.20.0") >= 0)
	if err != nil {
		return fmt.Errorf("create proxy certificate: %v", err)
	}
	data["ca.crt"] = caCert
	data["tls.crt"] = tlsCert
	data["tls.key"] = key
	if err != nil {
		return err
	}
	secretObj := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.PXC.SSLSecretName,
			Namespace: cr.Namespace,
		},
		Data: data,
		Type: corev1.SecretTypeTLS,
	}
	if cr.CompareVersionWith("1.16.0") >= 0 {
		secretObj.Labels = naming.LabelsCluster(cr)
	}
	err = r.client.Create(ctx, &secretObj)
	if err != nil && !k8serr.IsAlreadyExists(err) {
		return fmt.Errorf("create TLS secret: %v", err)
	}
	pxcHosts := []string{
		cr.Name + "-pxc",
		"*." + cr.Name + "-pxc",
		cr.Name + "-haproxy-replicas." + cr.Namespace + ".svc.cluster.local",
		cr.Name + "-haproxy-replicas." + cr.Namespace,
		cr.Name + "-haproxy-replicas",
		cr.Name + "-haproxy." + cr.Namespace + ".svc.cluster.local",
		cr.Name + "-haproxy." + cr.Namespace,
		cr.Name + "-haproxy",
	}
	if cr.Spec.TLS != nil && len(cr.Spec.TLS.SANs) > 0 {
		pxcHosts = append(pxcHosts, cr.Spec.TLS.SANs...)
	}
	caCert, tlsCert, key, err = pxctls.Issue(pxcHosts, cr.CompareVersionWith("1.19.0") >= 0, cr.CompareVersionWith("1.20.0") >= 0)
	if err != nil {
		return fmt.Errorf("create pxc certificate: %v", err)
	}
	data["ca.crt"] = caCert
	data["tls.crt"] = tlsCert
	data["tls.key"] = key
	secretObjInternal := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.PXC.SSLInternalSecretName,
			Namespace: cr.Namespace,
		},
		Data: data,
		Type: corev1.SecretTypeTLS,
	}
	if cr.CompareVersionWith("1.16.0") >= 0 {
		secretObjInternal.Labels = naming.LabelsCluster(cr)
	}
	err = r.client.Create(ctx, &secretObjInternal)
	if err != nil && !k8serr.IsAlreadyExists(err) {
		return fmt.Errorf("create TLS internal secret: %v", err)
	}
	return nil
}

func (r *ReconcilePerconaXtraDBCluster) createOrUpdateCertificate(ctx context.Context, desired *cm.Certificate) error {
	existing := &cm.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.client, existing, func() error {
		existing.Labels = desired.Labels

		// Preserve IssuerRef.Group if the API server defaulted it
		// (cert-manager >= 1.19 defaults empty group to "cert-manager.io").
		// Without this, every reconcile would see a diff and trigger
		// an unnecessary Update, which increments the Certificate's
		// generation and may cause cert-manager to re-issue.
		if desired.Spec.IssuerRef.Group == "" && existing.Spec.IssuerRef.Group != "" {
			desired.Spec.IssuerRef.Group = existing.Spec.IssuerRef.Group
		}

		existing.Spec = desired.Spec
		return nil
	})
	return err
}

// tlsCertConfig holds the resolved TLS configuration for building cert-manager Certificate objects.
type tlsCertConfig struct {
	issuerName   string
	caIssuerName string
	issuerKind   string
	issuerGroup  string
	caDuration   *metav1.Duration
	duration     *metav1.Duration
}

func resolveTLSCertConfig(cr *api.PerconaXtraDBCluster) tlsCertConfig {
	cfg := tlsCertConfig{
		issuerName:   cr.Name + "-pxc-issuer",
		caIssuerName: cr.Name + "-pxc-ca-issuer",
		issuerKind:   "Issuer",
		caDuration:   &metav1.Duration{Duration: pxctls.DefaultCAValidity},
		duration:     &metav1.Duration{Duration: pxctls.DefaultCertValidity},
	}
	if cr.Spec.TLS != nil {
		if cr.Spec.TLS.IssuerConf != nil {
			cfg.issuerKind = cr.Spec.TLS.IssuerConf.Kind
			cfg.issuerName = cr.Spec.TLS.IssuerConf.Name
			cfg.issuerGroup = cr.Spec.TLS.IssuerConf.Group
		}
		if cr.Spec.TLS.CADuration != nil {
			cfg.caDuration = cr.Spec.TLS.CADuration
		}
		if cr.Spec.TLS.Duration != nil {
			cfg.duration = cr.Spec.TLS.Duration
		}
	}
	return cfg
}

func buildCACertificate(cr *api.PerconaXtraDBCluster, cfg tlsCertConfig) *cm.Certificate {
	caCert := &cm.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-ca-cert",
			Namespace: cr.Namespace,
		},
		Spec: cm.CertificateSpec{
			SecretName: cr.Name + "-ca-cert",
			CommonName: cr.Name + "-ca",
			IsCA:       true,
			IssuerRef: cmmeta.ObjectReference{
				Name:  cfg.caIssuerName,
				Kind:  cfg.issuerKind,
				Group: cfg.issuerGroup,
			},
			Duration:    cfg.caDuration,
			RenewBefore: &metav1.Duration{Duration: pxctls.DefaultRenewBefore},
		},
	}
	if cr.CompareVersionWith("1.16.0") >= 0 {
		caCert.Labels = naming.LabelsCluster(cr)
	}
	return caCert
}

func buildSSLCertificate(cr *api.PerconaXtraDBCluster, cfg tlsCertConfig) *cm.Certificate {
	kubeCert := &cm.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-ssl",
			Namespace: cr.Namespace,
		},
		Spec: cm.CertificateSpec{
			SecretName: cr.Spec.PXC.SSLSecretName,
			CommonName: cr.Name + "-proxysql",
			DNSNames: []string{
				cr.Name + "-pxc",
				cr.Name + "-proxysql",
				"*." + cr.Name + "-pxc",
				"*." + cr.Name + "-proxysql",
			},
			IssuerRef: cmmeta.ObjectReference{
				Name:  cfg.issuerName,
				Kind:  cfg.issuerKind,
				Group: cfg.issuerGroup,
			},
		},
	}
	if cr.CompareVersionWith("1.16.0") >= 0 {
		kubeCert.Labels = naming.LabelsCluster(cr)
	}
	if cr.Spec.TLS != nil && len(cr.Spec.TLS.SANs) > 0 {
		kubeCert.Spec.DNSNames = append(kubeCert.Spec.DNSNames, cr.Spec.TLS.SANs...)
	}
	if cr.CompareVersionWith("1.19.0") >= 0 {
		kubeCert.Spec.Duration = cfg.duration
	}
	return kubeCert
}

func buildSSLInternalCertificate(cr *api.PerconaXtraDBCluster, cfg tlsCertConfig) *cm.Certificate {
	kubeCert := &cm.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-ssl-internal",
			Namespace: cr.Namespace,
		},
		Spec: cm.CertificateSpec{
			SecretName: cr.Spec.PXC.SSLInternalSecretName,
			CommonName: cr.Name + "-pxc",
			DNSNames: []string{
				cr.Name + "-pxc",
				"*." + cr.Name + "-pxc",
				cr.Name + "-haproxy-replicas." + cr.Namespace + ".svc.cluster.local",
				cr.Name + "-haproxy-replicas." + cr.Namespace,
				cr.Name + "-haproxy-replicas",
				cr.Name + "-haproxy." + cr.Namespace + ".svc.cluster.local",
				cr.Name + "-haproxy." + cr.Namespace,
				cr.Name + "-haproxy",
			},
			IssuerRef: cmmeta.ObjectReference{
				Name:  cfg.issuerName,
				Kind:  cfg.issuerKind,
				Group: cfg.issuerGroup,
			},
		},
	}
	if cr.Spec.TLS != nil && len(cr.Spec.TLS.SANs) > 0 {
		kubeCert.Spec.DNSNames = append(kubeCert.Spec.DNSNames, cr.Spec.TLS.SANs...)
	}
	if cr.CompareVersionWith("1.16.0") >= 0 {
		kubeCert.Labels = naming.LabelsCluster(cr)
	}
	if cr.CompareVersionWith("1.19.0") >= 0 {
		kubeCert.Spec.Duration = cfg.duration
	}
	return kubeCert
}

// reconcileCertManagerCertificateSpecs updates existing cert-manager Certificate
// CR specs to match the current PXC CR TLS configuration. Unlike createSSLByCertManager,
// it does not create issuers or wait for secrets since they already exist.
// It is a no-op if the Certificate CRs were not created by cert-manager.
func (r *ReconcilePerconaXtraDBCluster) reconcileCertManagerCertificateSpecs(ctx context.Context, cr *api.PerconaXtraDBCluster) error {
	// Only reconcile if the SSL certificate was created by cert-manager.
	sslCert := &cm.Certificate{}
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      cr.Name + "-ssl",
	}, sslCert); err != nil {
		if k8serr.IsNotFound(err) {
			// Certificate CR doesn't exist — certs were created manually.
			return nil
		}
		return fmt.Errorf("get ssl certificate: %w", err)
	}

	cfg := resolveTLSCertConfig(cr)

	// Update CA certificate spec if using built-in issuer
	if cr.Spec.TLS == nil || cr.Spec.TLS.IssuerConf == nil {
		// Confirm the CA issuer exists before attempting updates.
		caIssuer := &cm.Issuer{}
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: cr.Namespace,
			Name:      cfg.caIssuerName,
		}, caIssuer); err != nil {
			if k8serr.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("get CA issuer: %w", err)
		}

		caCert := buildCACertificate(cr, cfg)
		if err := r.createOrUpdateCertificate(ctx, caCert); err != nil {
			return fmt.Errorf("update CA certificate: %w", err)
		}
	}

	// Update SSL certificate spec
	kubeCert := buildSSLCertificate(cr, cfg)
	if err := r.createOrUpdateCertificate(ctx, kubeCert); err != nil {
		return fmt.Errorf("update certificate: %w", err)
	}

	// Update SSL internal certificate spec
	if cr.Spec.PXC.SSLSecretName != cr.Spec.PXC.SSLInternalSecretName {
		kubeCertInternal := buildSSLInternalCertificate(cr, cfg)
		if err := r.createOrUpdateCertificate(ctx, kubeCertInternal); err != nil {
			return fmt.Errorf("update internal certificate: %w", err)
		}
	}

	return nil
}

func (r *ReconcilePerconaXtraDBCluster) reconcileTLSToggle(ctx context.Context, cr *api.PerconaXtraDBCluster) error {
	if cr.CompareVersionWith("1.16.0") < 0 {
		return nil
	}

	condition := cr.Status.FindCondition(naming.ConditionTLS)
	if condition == nil {
		cr.Status.AddCondition(api.ClusterCondition{
			Type:               naming.ConditionTLS,
			Status:             api.ConditionStatus(naming.GetConditionTLSState(cr)),
			LastTransitionTime: metav1.NewTime(time.Now().Truncate(time.Second)),
		})
		return nil
	}

	if condition.Status == api.ConditionStatus(naming.GetConditionTLSState(cr)) {
		return nil
	}

	clusterPaused, err := k8s.PauseCluster(ctx, r.client, cr)
	if err != nil {
		return errors.Wrap(err, "failed to pause cluster")
	}
	if !clusterPaused {
		return nil
	}

	switch naming.ConditionTLSState(condition.Status) {
	case naming.ConditionTLSStateEnabled:
		if err := r.deleteCerts(ctx, cr); err != nil {
			return errors.Wrap(err, "failed to delete tls secrets")
		}
	case naming.ConditionTLSStateDisabled:
	default:
		return errors.Errorf("unknown value for %s condition status: %s", naming.ConditionTLS, condition.Status)
	}

	patch := client.MergeFrom(cr.DeepCopy())
	cr.Spec.Unsafe.TLS = !*cr.Spec.TLS.Enabled
	if err := r.client.Patch(ctx, cr.DeepCopy(), patch); err != nil {
		return errors.Wrap(err, "failed to patch cr")
	}

	_, err = k8s.UnpauseCluster(ctx, r.client, cr)
	if err != nil {
		return errors.Wrap(err, "failed to start cluster")
	}

	condition.Status = api.ConditionStatus(naming.GetConditionTLSState(cr))
	condition.LastTransitionTime = metav1.NewTime(time.Now().Truncate(time.Second))
	return nil
}
