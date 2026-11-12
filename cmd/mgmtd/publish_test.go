package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestPublishPublicKey(t *testing.T) {
	client := fake.NewClientset()
	var managers []string
	client.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		managers = append(managers, "create:"+a.(ktesting.CreateActionImpl).CreateOptions.FieldManager)
		return false, nil, nil
	})
	client.PrependReactor("update", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		managers = append(managers, "update:"+a.(ktesting.UpdateActionImpl).UpdateOptions.FieldManager)
		return false, nil, nil
	})
	pub, priv := newKey(t)
	ctx := t.Context()

	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(pub)
	if cm.Data["spec.pub"] != want || cm.Labels["cell.poc.internal/harness"] != "mgmt-api" || cm.Labels["poc.internal/made-by"] != "mgmtd" {
		t.Fatalf("created ConfigMap: data %v labels %v", cm.Data, cm.Labels)
	}
	if len(managers) != 1 || managers[0] != "create:mgmtd" {
		t.Fatalf("create field manager: %v", managers)
	}

	// A second publish of the same key changes nothing.
	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub); err != nil {
		t.Fatal(err)
	}
	if len(managers) != 1 {
		t.Fatalf("an unchanged publish wrote again: %v", managers)
	}

	// A wrong value and a lost label are repaired, and an unrelated key stays.
	cm.Data["spec.pub"] = "AAAA"
	cm.Data["other"] = "keep"
	cm.Labels = map[string]string{"x": "y"}
	if _, err := client.CoreV1().ConfigMaps("mgmt-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	managers = nil
	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub); err != nil {
		t.Fatal(err)
	}
	cm, _ = client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
	if cm.Data["spec.pub"] != want || cm.Data["other"] != "keep" || cm.Labels["poc.internal/made-by"] != "mgmtd" || cm.Labels["x"] != "y" {
		t.Fatalf("repaired ConfigMap: data %v labels %v", cm.Data, cm.Labels)
	}
	if len(managers) != 1 || managers[0] != "update:mgmtd" {
		t.Fatalf("update field manager: %v", managers)
	}

	// The ConfigMap holds the public key only.
	var all bytes.Buffer
	for _, v := range cm.Data {
		all.WriteString(v)
	}
	if strings.Contains(all.String(), base64.StdEncoding.EncodeToString(priv)) || strings.Contains(all.String(), base64.StdEncoding.EncodeToString(priv.Seed())) {
		t.Fatal("the ConfigMap holds private key bytes")
	}

	if err := PublishPublicKey(ctx, client, "mgmt-system", "x", ed25519.PublicKey("short")); err == nil {
		t.Fatal("a key of the wrong size was published")
	}
}

func TestPublishPublicKeyErrors(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("api server down")
	})
	pub, _ := newKey(t)
	if err := PublishPublicKey(t.Context(), client, "mgmt-system", "mgmt-signing-pub", pub); err == nil {
		t.Fatal("no error from a failing API server")
	}
	_ = corev1.ConfigMap{}
}

func TestPublisherRetriesUntilItSucceeds(t *testing.T) {
	pub, _ := newKey(t)
	var calls atomic.Int32
	done := make(chan struct{})
	var once sync.Once
	publish := func(_ context.Context, got ed25519.PublicKey) error {
		if !got.Equal(pub) {
			t.Error("wrong key")
		}
		if calls.Add(1) < 3 {
			return errors.New("not yet")
		}
		once.Do(func() { close(done) })
		return nil
	}
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	nudge := make(chan struct{}, 1)
	go runPublisher(ctx, func() ed25519.PublicKey { return pub }, publish, nudge, jsonLogger(&logs), time.Millisecond, time.Hour)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no success after %d calls", calls.Load())
	}
	// A nudge publishes again, for example after a rotation.
	n := calls.Load()
	nudge <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() == n {
		t.Fatal("a nudge did not publish")
	}
	if !strings.Contains(logs.String(), "public_key_publish_failed") || !strings.Contains(logs.String(), "public_key_published") {
		t.Fatalf("log: %s", logs.String())
	}
}
