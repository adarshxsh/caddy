package caddytls

import (
	"context"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/cloudflare/circl/hpke"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type mockPublisher struct {
	key string
}

func (m *mockPublisher) PublisherKey() string {
	if m.key != "" {
		return m.key
	}
	return "mock_publisher"
}

func (m *mockPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, configList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestCloneECHConfig(t *testing.T) {
	// 1. Test nil publicationHistory Clone
	var nilHist publicationHistory
	clonedNil := nilHist.Clone()
	if clonedNil == nil {
		t.Fatalf("expected cloned nil publicationHistory to be non-nil empty map")
	}
	// Writing to clonedNil should not panic
	clonedNil["pub1"] = map[string]time.Time{"example.com": time.Now()}

	// 2. Test deep copy independence of publicationHistory
	now := time.Now()
	origHist := publicationHistory{
		"pub1": {
			"example.com": now,
		},
	}
	clonedHist := origHist.Clone()
	clonedHist["pub1"]["example.com"] = now.Add(1 * time.Hour)
	clonedHist["pub2"] = map[string]time.Time{"sub.example.com": now}

	if origHist["pub1"]["example.com"].Equal(clonedHist["pub1"]["example.com"]) {
		t.Fatalf("modifying cloned publicationHistory inner map mutated original")
	}
	if _, ok := origHist["pub2"]; ok {
		t.Fatalf("adding key to cloned publicationHistory mutated original")
	}

	// 3. Test echConfigMeta Clone
	origMeta := echConfigMeta{
		Created:      now,
		Replaced:     now.Add(24 * time.Hour),
		Publications: origHist,
	}
	clonedMeta := origMeta.Clone()
	clonedMeta.Publications["pub1"]["example.com"] = now.Add(2 * time.Hour)

	if origMeta.Publications["pub1"]["example.com"].Equal(clonedMeta.Publications["pub1"]["example.com"]) {
		t.Fatalf("modifying cloned echConfigMeta Publications mutated original")
	}

	// 4. Test echConfig Clone
	pubKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	origCfg := echConfig{
		Version:       draftTLSESNI25,
		ConfigID:      1,
		KEMID:         hpke.KEM_X25519_HKDF_SHA256,
		PublicKey:     pubKey,
		MaxNameLength: 32,
		RawPublicName: "public.example.com",
		CipherSuites: []hpkeSymmetricCipherSuite{
			{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_AES128GCM},
		},
		RawExtensions: []byte{1, 2, 3},
		configBin:     []byte{4, 5, 6},
		privKeyBin:    []byte{7, 8, 9},
		meta:          origMeta,
	}

	clonedCfg := origCfg.Clone()

	// Mutate slices and maps on clonedCfg
	clonedCfg.CipherSuites[0].AEADID = hpke.AEAD_AES256GCM
	clonedCfg.RawExtensions[0] = 99
	clonedCfg.configBin[0] = 99
	clonedCfg.privKeyBin[0] = 99
	clonedCfg.meta.Publications["pub1"]["example.com"] = now.Add(3 * time.Hour)

	if origCfg.CipherSuites[0].AEADID == hpke.AEAD_AES256GCM {
		t.Fatalf("modifying cloned CipherSuites mutated original")
	}
	if origCfg.RawExtensions[0] == 99 || origCfg.configBin[0] == 99 || origCfg.privKeyBin[0] == 99 {
		t.Fatalf("modifying cloned byte slices mutated original")
	}
	if origCfg.meta.Publications["pub1"]["example.com"].Equal(clonedCfg.meta.Publications["pub1"]["example.com"]) {
		t.Fatalf("modifying cloned meta Publications mutated original")
	}
}

func TestConcurrentPublishAndRotateECHKeys(t *testing.T) {
	tempDir := t.TempDir()
	storage := &certmagic.FileStorage{Path: tempDir}

	origStorage := certmagic.Default.Storage
	certmagic.Default.Storage = storage
	t.Cleanup(func() {
		certmagic.Default.Storage = origStorage
	})

	var caddyCfg caddy.Config
	ctx, err := caddy.ProvisionContext(&caddyCfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	logger := zap.NewNop()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{&mockPublisher{key: "test_pub"}},
			},
		},
	}

	// Create initial configs in storage and memory
	for id := uint8(1); id <= 3; id++ {
		numStr := strconv.Itoa(int(id))
		parentKey := path.Join(echConfigsKey, numStr)

		pubKey, privKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}

		cfg := echConfig{
			Version:       draftTLSESNI25,
			ConfigID:      id,
			KEMID:         hpke.KEM_X25519_HKDF_SHA256,
			PublicKey:     pubKey,
			MaxNameLength: 32,
			RawPublicName: "public.example.com",
			CipherSuites: []hpkeSymmetricCipherSuite{
				{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_AES128GCM},
			},
			meta: echConfigMeta{
				Created:      time.Now(),
				Publications: make(publicationHistory),
			},
		}

		privBytes, _ := privKey.MarshalBinary()
		cfgBytes, _ := cfg.MarshalBinary()
		cfg.configBin = cfgBytes
		cfg.privKeyBin = privBytes

		_ = storage.Store(ctx, path.Join(parentKey, "key.bin"), cfg.privKeyBin)
		_ = storage.Store(ctx, path.Join(parentKey, "config.bin"), cfg.configBin)

		ech.configs["public.example.com"] = append(ech.configs["public.example.com"], cfg)
	}

	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               logger,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"inner.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// Goroutine 1 & 2: Publish ECH configs
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					_ = tlsApp.publishECHConfigs(logger)
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Goroutine 3 & 4: Concurrently mutate/rotate ECH keys under lock
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					ech.configsMu.Lock()
					cfgs := ech.configs["public.example.com"]
					if len(cfgs) > 0 {
						// Mutate metadata / publications on target config
						idx := gid % len(cfgs)
						if cfgs[idx].meta.Publications == nil {
							cfgs[idx].meta.Publications = make(publicationHistory)
						}
						cfgs[idx].meta.Publications["test_pub"] = map[string]time.Time{
							"inner.example.com": time.Now(),
						}
						cfgs[idx].meta.Created = time.Now().Add(-time.Duration(gid) * time.Hour)
					}
					ech.configsMu.Unlock()

					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stopChan)
	wg.Wait()
}

func TestPublishECHConfigHandlesDeletedConfigID(t *testing.T) {
	tempDir := t.TempDir()
	storage := &certmagic.FileStorage{Path: tempDir}

	origStorage := certmagic.Default.Storage
	certmagic.Default.Storage = storage
	t.Cleanup(func() {
		certmagic.Default.Storage = origStorage
	})

	var caddyCfg caddy.Config
	ctx, err := caddy.ProvisionContext(&caddyCfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	logger := zap.NewNop()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{&mockPublisher{key: "test_pub"}},
			},
		},
	}

	pubKey, privKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	cfg := echConfig{
		Version:       draftTLSESNI25,
		ConfigID:      10,
		KEMID:         hpke.KEM_X25519_HKDF_SHA256,
		PublicKey:     pubKey,
		MaxNameLength: 32,
		RawPublicName: "public.example.com",
		CipherSuites: []hpkeSymmetricCipherSuite{
			{KDFID: hpke.KDF_HKDF_SHA256, AEADID: hpke.AEAD_AES128GCM},
		},
		meta: echConfigMeta{
			Created:      time.Now(),
			Publications: make(publicationHistory),
		},
	}

	privBytes, _ := privKey.MarshalBinary()
	cfgBytes, _ := cfg.MarshalBinary()
	cfg.configBin = cfgBytes
	cfg.privKeyBin = privBytes

	ech.configs["public.example.com"] = []echConfig{cfg}

	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               logger,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"inner.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	// Simulate config being deleted before write-back by clearing ech.configs right before or during
	// publishECHConfigs call using a custom publisher that deletes the config in publish
	deletingPub := &deletingPublisher{
		key:    "test_pub",
		tlsApp: tlsApp,
	}
	ech.Publication[0].publishers = []ECHPublisher{deletingPub}

	err = tlsApp.publishECHConfigs(logger)
	if err != nil {
		t.Fatalf("publishECHConfigs failed unexpectedly: %v", err)
	}
}

type deletingPublisher struct {
	key    string
	tlsApp *TLS
}

func (d *deletingPublisher) PublisherKey() string {
	return d.key
}

func (d *deletingPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, configList []byte) error {
	// Simulate rotation deleting the config while publishing is in progress
	d.tlsApp.EncryptedClientHello.configsMu.Lock()
	d.tlsApp.EncryptedClientHello.configs["public.example.com"] = nil
	d.tlsApp.EncryptedClientHello.configsMu.Unlock()
	return nil
}
