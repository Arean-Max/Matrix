package api

import "eventhorizon/internal/wire"

func validateFingerprint(fp string) error {
	if !wire.ValidFingerprint(fp) {
		return missingField("fingerprint")
	}
	return nil
}
