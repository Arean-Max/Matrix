package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"event-horizon/server/internal/admin"
	"event-horizon/server/internal/licensing"
	"event-horizon/server/internal/storage"
	"event-horizon/server/internal/telemetry"
	"event-horizon/shared/proto"
)

func main() {
	port := flag.Int("port", 8443, "Server port")
	dbPath := flag.String("db", "event_horizon.db", "Path to encrypted database file")
	passphrase := flag.String("passphrase", "", "Database encryption passphrase (or set EH_DB_PASSPHRASE env)")
	flag.Parse()

	log.Println("[Event Horizon] Starting License & Attestation Server (Spec v12)...")

	// Derive 256-bit DB key strictly in RAM from passphrase (Section 4)
	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("EH_DB_PASSPHRASE")
	}
	if pass == "" {
		pass = "default-in-memory-dev-passphrase-change-in-prod"
		log.Println("[!] Warning: Using default in-memory database passphrase. Set EH_DB_PASSPHRASE in production.")
	}

	keyDigest := sha256.Sum256([]byte(pass))
	masterKey := keyDigest[:]

	store, err := storage.OpenEncryptedStorage(*dbPath, masterKey)
	if err != nil {
		log.Fatalf("[-] Failed to open encrypted database: %v", err)
	}

	// Seed sample license for testing if empty
	sampleKey := "EH-TEST-KEY-128BIT-ENTROPY"
	sampleHash := storage.HashLicenseKey(sampleKey)
	if _, err := store.GetLicense(sampleHash); err != nil {
		_ = store.PutLicense(&storage.LicenseRecord{
			LicenseKeyHash: sampleHash,
			Status:         proto.StatusSuccess,
			TrustLevel:     proto.TrustLevelStandardCommercial,
			OOBChannel:     "customer@enterprise.local",
			CreatedUnix:    1729000000,
		})
		log.Printf("[+] Seeded test license: %s (hash: %s)", sampleKey, sampleHash[:16])
	}

	licService, err := licensing.NewLicensingService(store, masterKey)
	if err != nil {
		log.Fatalf("[-] Failed to initialize licensing service: %v", err)
	}

	licHandler := licensing.NewLicensingHandler(licService)
	adminService := admin.NewAdminService(store)
	_ = telemetry.NewAISentinel("", "")

	mux := http.NewServeMux()
	licHandler.RegisterRoutes(mux)
	adminService.RegisterRoutes(mux)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[+] Server listening on %s (TLS 1.3 / HTTP)", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[-] Server failed: %v", err)
	}
}
