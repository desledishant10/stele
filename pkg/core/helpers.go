package core

import (
	"encoding/json"

	"github.com/desledishant10/stele/pkg/anchor"
)

func serialiseAnchorRecord(r *anchor.Record) ([]byte, error) {
	return json.Marshal(r)
}
