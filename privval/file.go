package privval

import (
	cmtprivval "github.com/cometbft/cometbft/privval"
)

// var _ keeper.BlsSigner = &WrappedFilePV{}

// WrappedFilePV is a wrapper around cmtprivval.FilePV
type WrappedFilePV struct {
	Comet cmtprivval.FilePVKey
	Bls   BlsPVKey
}

// NewWrappedFilePV creates a new WrappedFilePV
func NewWrappedFilePV(comet cmtprivval.FilePVKey, bls BlsPVKey) *WrappedFilePV {
	return &WrappedFilePV{
		Comet: comet,
		Bls:   bls,
	}
}
