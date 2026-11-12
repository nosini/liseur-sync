package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/chmouel/liseur-sync/internal/store"
)

// testPersonalMirrors covers the sealed per-account mirror rows
// (ADR-F001): each account reads and replaces only its own, and the
// target digest is unique across accounts while it is set.
func testPersonalMirrors(t *testing.T, open OpenFunc) {
	s := open(t)
	ctx := context.Background()
	alice := MkUser(t, s, "personal-alice")
	bob := MkUser(t, s, "personal-bob")

	if _, err := s.PersonalMirror(ctx, alice.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no row yet: %v", err)
	}
	if err := s.PutPersonalMirror(ctx, store.PersonalMirror{
		UserID: alice.ID, SealedConfig: "sealed-a1", TargetHash: "target-1",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.PersonalMirror(ctx, alice.ID)
	if err != nil || got.SealedConfig != "sealed-a1" || got.TargetHash != "target-1" {
		t.Fatalf("alice: %+v %v", got, err)
	}
	if _, err := s.PersonalMirror(ctx, bob.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob read a row he never wrote: %v", err)
	}

	// One remote account, two local ones: refused by the database.
	err = s.PutPersonalMirror(ctx, store.PersonalMirror{
		UserID: bob.ID, SealedConfig: "sealed-b1", TargetHash: "target-1",
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second account took the same target: %v", err)
	}
	if _, err := s.PersonalMirror(ctx, bob.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused row was written: %v", err)
	}
	// Disabled mirrors hold no target, and any number of them coexist.
	for _, u := range []store.User{alice, bob} {
		if err := s.PutPersonalMirror(ctx, store.PersonalMirror{
			UserID: u.ID, SealedConfig: "disabled-" + u.ID,
		}); err != nil {
			t.Fatalf("%s disabled: %v", u.Name, err)
		}
	}
	got, err = s.PersonalMirror(ctx, alice.ID)
	if err != nil || got.SealedConfig != "disabled-"+alice.ID || got.TargetHash != "" {
		t.Fatalf("replacement: %+v %v", got, err)
	}

	// The manager's fill-in applies only to the row it read.
	if err := s.SetPersonalMirrorTarget(ctx, bob.ID, "stale", "target-2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PersonalMirror(ctx, bob.ID); got.TargetHash != "" {
		t.Fatalf("a stale fill-in overwrote a newer save: %+v", got)
	}
	if err := s.SetPersonalMirrorTarget(ctx, bob.ID, "disabled-"+bob.ID, "target-2"); err != nil {
		t.Fatal(err)
	}
	err = s.SetPersonalMirrorTarget(ctx, alice.ID, "disabled-"+alice.ID, "target-2")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("fill-in took another account's target: %v", err)
	}

	all, err := s.ListPersonalMirrors(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %+v %v", all, err)
	}
	if err := s.DeletePersonalMirror(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PersonalMirror(ctx, bob.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted row still there: %v", err)
	}
	if got, err := s.PersonalMirror(ctx, alice.ID); err != nil || got.SealedConfig != "disabled-"+alice.ID {
		t.Fatalf("deleting bob's touched alice's: %+v %v", got, err)
	}
	// With bob's gone, his target is free again.
	if err := s.SetPersonalMirrorTarget(ctx, alice.ID, "disabled-"+alice.ID, "target-2"); err != nil {
		t.Fatal(err)
	}
}
