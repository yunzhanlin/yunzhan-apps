package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestIntegrityKernelApplicationIdentityKeepsPublishedWebsiteBytes(t *testing.T) {
	old := integrityKernelRequestFixture()
	if got := IntegrityKernelRequestSHA(old); got != "a145ba1a816c689231e3b288930a83498a79f114e2d3dec4e7d35c0bb201b6ce" {
		t.Fatal("published website request digest changed", got)
	}
	raw, _ := json.Marshal(old)
	if strings.Contains(string(raw), "app_id") {
		t.Fatal("legacy request gained a new serialized field", string(raw))
	}
	enterprise := NewIntegrityKernelApplicationRequest(IntegrityKernelEnterpriseApplication, old)
	if ValidateIntegrityKernelRequest(enterprise) != nil || IntegrityKernelRequestSHA(enterprise) != "6f106b10ec4d8b6e919cca31d6ed2b9bf7e1bb318e0b84f377f3df4e767815cd" {
		t.Fatal("enterprise original identity differs from independent JSON fixture", enterprise)
	}
	if IntegrityKernelSubmissionID(old.ActorID, "original-key", IntegrityKernelWebsiteApplication, false) != "bc7926e49fcda298a324b77c289b9cd5" || IntegrityKernelSubmissionID(old.ActorID, "original-key", IntegrityKernelEnterpriseApplication, false) != "5e77691999839fa0000206847a0973c7" || IntegrityKernelSubmissionID(old.ActorID, "original-key", IntegrityKernelEnterpriseApplication, true) != "a21a56f6583df0caa650e767a5f15462" {
		t.Fatal("original actor/key identity crossed applications or close/operation types")
	}
	for _, bad := range []IntegrityKernelRequest{
		{Format: 1, AppID: IntegrityKernelEnterpriseApplication},
		{Format: 1, AppID: IntegrityKernelWebsiteApplication},
		{Format: 2}, {Format: 2, AppID: IntegrityKernelWebsiteApplication},
		{Format: 2, AppID: "file-monitor"}, {Format: 3, AppID: IntegrityKernelEnterpriseApplication},
	} {
		candidate := old
		candidate.Format, candidate.AppID = bad.Format, bad.AppID
		if ValidateIntegrityKernelRequest(candidate) == nil {
			t.Fatal("alias or foreign application obtained an inode-control identity", candidate)
		}
	}
}

func TestIntegrityKernelEnterpriseAuthorityCannotBorrowWebsiteReceipt(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "enterprise-inode-authority", "", nil)
	access, err := s.UserAccess(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	request := NewIntegrityKernelApplicationRequest(IntegrityKernelEnterpriseApplication, integrityKernelRequestFixture())
	request.ActorID, request.AccessRevision = admin.ID, access.Revision
	if _, err = s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('website-tamper-proof','website-tamper-proof',?,?,'website-tamper-proof',?)`, IntegrityKernelAppVersion, request.AppSHA, Now()); err != nil {
		t.Fatal(err)
	}
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("website signed receipt authorized enterprise kernel access")
	}
	enterpriseSHA := strings.Repeat("c", 64)
	if _, err = s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('enterprise-tamper-proof','enterprise-tamper-proof',?,?,'enterprise-tamper-proof',?)`, IntegrityKernelAppVersion, enterpriseSHA, Now()); err != nil {
		t.Fatal(err)
	}
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("enterprise request borrowed a different signed package digest")
	}
	request.AppSHA = enterpriseSHA
	if err = s.ValidateIntegrityKernelAuthority(context.Background(), request); err != nil {
		t.Fatal("own exact enterprise receipt was refused", err)
	}
	website := NewIntegrityKernelApplicationRequest(IntegrityKernelWebsiteApplication, request)
	if s.ValidateIntegrityKernelAuthority(context.Background(), website) == nil {
		t.Fatal("enterprise signed package digest authorized website control")
	}
	if _, err = s.DB.Exec(`UPDATE app_registry_receipts SET target='file-monitor' WHERE app_id='enterprise-tamper-proof'`); err != nil {
		t.Fatal(err)
	}
	if s.ValidateIntegrityKernelAuthority(context.Background(), request) == nil {
		t.Fatal("foreign delivery target authorized enterprise control")
	}
}

func TestIntegrityKernelOtherApplicationStatusNeverOffersBorrowedOwnership(t *testing.T) {
	r := integrityKernelRequestFixture()
	op := IntegrityKernelOperation{Request: r, RequestSHA: IntegrityKernelRequestSHA(r), State: "succeeded", Revision: 1, PlanSHA: strings.Repeat("d", 64), EnableOperation: r.ID, Files: 1, Directories: 1, Completed: 2, FinishedAt: Now()}
	status := IntegrityKernelStatus{AppID: IntegrityKernelEnterpriseApplication, SiteID: r.Input.SiteID, AppVersion: IntegrityKernelAppVersion, AppSHA: strings.Repeat("e", 64), Revision: 1, State: "other-application", VerifiedAt: Now(), Operations: []IntegrityKernelOperation{op}, Latest: &op}
	if !ValidIntegrityKernelStatus(status) {
		t.Fatal("truthful foreign ownership could not be displayed")
	}
	status.State = "enabled"
	if ValidIntegrityKernelStatus(status) {
		t.Fatal("foreign protection was displayed as own enterprise enablement")
	}
	status.State = "other-application"
	status.AppID = ""
	if ValidIntegrityKernelStatus(status) {
		t.Fatal("own protection was mislabeled as another application's")
	}
	foreign := NewIntegrityKernelApplicationRequest(IntegrityKernelEnterpriseApplication, r)
	foreign.ID, foreign.Action, foreign.Input.ExpectedRevision = ID(), "release", 1
	foreign.Input.BaselineSHA, foreign.Input.SourceOperation, foreign.Input.SourceSHA, foreign.Input.Confirm = "", r.ID, op.RequestSHA, "RELEASE SITE "+r.Input.SiteID
	release := IntegrityKernelOperation{Request: foreign, RequestSHA: IntegrityKernelRequestSHA(foreign), State: "succeeded", Revision: 2, FinishedAt: Now()}
	status.AppID, status.State, status.Revision = IntegrityKernelEnterpriseApplication, "released", 2
	status.Operations, status.Latest = []IntegrityKernelOperation{op, release}, &release
	if ValidIntegrityKernelStatus(status) {
		t.Fatal("cross-application release chain passed despite a matching source digest")
	}
}
