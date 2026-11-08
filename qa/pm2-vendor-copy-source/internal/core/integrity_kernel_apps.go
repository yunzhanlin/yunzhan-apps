package core

// The two applications share one original-operation journal and per-site
// revision chain. A second application cannot adopt or release the first
// application's protection, nor consume a separate unaccounted release budget.
// Format1 remains byte-identical for the published website1.5 records.
const IntegrityKernelWebsiteApplication = "website-tamper-proof"
const IntegrityKernelEnterpriseApplication = "enterprise-tamper-proof"

type IntegrityKernelApplicationRoute struct {
	Application string
	API         string
	Executor    string
}

func IntegrityKernelApplicationRoutes() []IntegrityKernelApplicationRoute {
	return []IntegrityKernelApplicationRoute{
		{IntegrityKernelWebsiteApplication, "/api/app-modules/website-tamper-proof/kernel", "/v1/integrity-kernel"},
		{IntegrityKernelEnterpriseApplication, "/api/app-modules/enterprise-tamper-proof/kernel", "/v1/enterprise-integrity-kernel"},
	}
}

func ValidIntegrityKernelApplication(application string) bool {
	return application == IntegrityKernelWebsiteApplication || application == IntegrityKernelEnterpriseApplication
}

func IntegrityKernelRequestApplication(request IntegrityKernelRequest) string {
	if request.Format == 1 && request.AppID == "" {
		return IntegrityKernelWebsiteApplication
	}
	if request.Format == 2 && request.AppID == IntegrityKernelEnterpriseApplication {
		return IntegrityKernelEnterpriseApplication
	}
	return ""
}

func IntegrityKernelStatusApplication(status IntegrityKernelStatus) string {
	if status.AppID == "" {
		return IntegrityKernelWebsiteApplication
	}
	if status.AppID == IntegrityKernelEnterpriseApplication {
		return IntegrityKernelEnterpriseApplication
	}
	return ""
}

func IntegrityKernelSubmissionID(actor, key, application string, close bool) string {
	if !ValidID(actor) || !ValidIntegrityKernelApplication(application) {
		return ""
	}
	kind := "operation"
	if close {
		kind = "close"
	}
	if application == IntegrityKernelWebsiteApplication {
		return Hash("integrity-kernel-" + kind + "-v1\x00" + actor + "\x00" + key)[:32]
	}
	return Hash("integrity-kernel-" + kind + "-v2\x00" + application + "\x00" + actor + "\x00" + key)[:32]
}

func NewIntegrityKernelApplicationRequest(application string, request IntegrityKernelRequest) IntegrityKernelRequest {
	if application == IntegrityKernelWebsiteApplication {
		request.Format, request.AppID = 1, ""
	} else if application == IntegrityKernelEnterpriseApplication {
		request.Format, request.AppID = 2, application
	} else {
		request.Format, request.AppID = 0, ""
	}
	return request
}

func IntegrityKernelOperationReleased(operation IntegrityKernelOperation) bool {
	return operation.State == "succeeded" && operation.Request.Action == "release" || (operation.State == "declined" || operation.State == "cancelled") && operation.Request.Action == "enable"
}

func IntegrityKernelAdmissionApplicationMatches(admission IntegrityKernelAdmission, application string) bool {
	if !ValidIntegrityKernelApplication(application) {
		return false
	}
	return (admission.Operation == nil || IntegrityKernelRequestApplication(admission.Operation.Request) == application) && (admission.Closure == nil || IntegrityKernelRequestApplication(admission.Closure.Request) == application)
}
