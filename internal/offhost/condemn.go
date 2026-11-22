package offhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// The two-phase delete. A collection never deletes a snapshot that an
// upload may have just checked and gone on to build on. It condemns it
// first and then looks; an upload pins it first and then checks:
//
//	collector                          uploader
//	1. copy manifest -> condemned      a. write pin/<random>
//	2. delete manifest                 b. read the manifest, check chunks
//	3. list the snapshot's prefix
//	4. a pin: manifest put back;
//	   none: chunks, then condemned go
//
// Whichever of 2 and a comes second sees the first, on a service whose
// listings show every write that finished before they began: if the
// uploader's read (b) found the manifest, it came before 2, so its pin
// (a) came before 3 and the collector puts the manifest back; if the
// collector's listing (3) found no pin, the pin came after 3, so after
// 2, and the uploader's read finds no manifest and builds on nothing.
// See Collect for the rules that make this hold across collectors,
// crashes and time, and AUDIT_OPEN.md for the interleavings.

const (
	condemnedName = "condemned"
	pinDir        = "pin"
	// pinBody is what a pin holds. It is unauthenticated, like every
	// object name: a pin only ever keeps a snapshot longer.
	pinBody = "pin\n"
)

func (s *Store) condemnedKey(id string) string { return s.snapshotPrefix(id) + condemnedName }
func (s *Store) pinPrefix(id string) string    { return s.snapshotPrefix(id) + pinDir + "/" }

// validPin is the shape of a pin's name.
func validPin(name string) bool { return validAttempt(name) }

// Pin writes a pin under a snapshot's prefix, under a name no one else
// will ever write or delete before it has aged: a collection that has
// condemned the snapshot and sees it puts the manifest back. Every pin
// has a fresh name on purpose. A collector deletes only a pin it has
// itself watched for the grace; a name written again in between would
// be deleted as the old one, and the write it carried lost.
func (s *Store) Pin(ctx context.Context, id string) error {
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	return s.objects.Put(ctx, s.pinPrefix(id)+hex.EncodeToString(token), []byte(pinBody), s3.PutOptions{ContentType: "text/plain"})
}
