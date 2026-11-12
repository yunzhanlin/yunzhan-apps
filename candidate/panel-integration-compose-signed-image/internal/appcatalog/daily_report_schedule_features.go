package appcatalog

import "errors"

const DailyReportScheduleFeature = "daily-report-schedule-v1"
const DailyReportScheduleVersion = "1.4.1"

func validateDailyReportScheduleRequirement(m Manifest, available func(string) bool) (bool, error) {
	comparison, comparable := CompareVersions(m.Version, DailyReportScheduleVersion)
	required := m.ID == "daily-report" && comparable && comparison >= 0
	for _, feature := range m.RequiredPanelFeatures {
		required = required || feature == DailyReportScheduleFeature
	}
	if !required {
		return false, nil
	}
	if m.ID != "daily-report" || m.Version != DailyReportScheduleVersion || m.Delivery.Provider != "panel-module" ||
		m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 ||
		m.RequiredPanelFeatures[0] != DailyReportScheduleFeature {
		return true, errors.New("日报生成时间须绑定完整版本和面板处理器")
	}
	if available == nil || !available(DailyReportScheduleFeature) {
		return true, errors.New("当前面板缺少日报生成时间处理器，请先升级面板")
	}
	return true, nil
}
