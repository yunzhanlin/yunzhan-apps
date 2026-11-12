package appcatalog

import "errors"

const FTPTransferHistoryFeature = "pure-ftpd-transfer-history-v1"
const FTPTransferHistoryVersion = "1.0.54-compat7"

func validateFTPTransferHistoryRequirement(m Manifest, available func(string) bool) (bool, error) {
	comparison, comparable := CompareVersions(m.Version, FTPTransferHistoryVersion)
	required := m.ID == "pure-ftpd" && comparable && comparison >= 0
	for _, feature := range m.RequiredPanelFeatures {
		required = required || feature == FTPTransferHistoryFeature
	}
	if !required {
		return false, nil
	}
	if m.ID != "pure-ftpd" || m.Version != FTPTransferHistoryVersion || m.Delivery.Provider != "panel-module" ||
		m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 ||
		m.RequiredPanelFeatures[0] != FTPTransferHistoryFeature {
		return true, errors.New("Pure-FTPd 传输日志须绑定完整版本和独立处理器声明")
	}
	if available == nil || !available(FTPTransferHistoryFeature) {
		return true, errors.New("当前面板缺少 Pure-FTPd 传输日志处理器，请先升级面板")
	}
	return true, nil
}
