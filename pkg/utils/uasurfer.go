package utils

import (
	"fmt"
	"strings"

	"github.com/LumenResearch/uasurfer"
)

type ClientInfo struct {
	Type    string
	Browser string
	OS      string
	IsBot   bool
	Raw     string
}

func ParseUA(uaStr string) string {
	// 🔒 safety: limit length
	if len(uaStr) > 300 {
		uaStr = uaStr[:300]
	}

	ua := uasurfer.Parse(uaStr)

	isBot := isBotUA(uaStr)

	clientInfo := ClientInfo{
		Type:    detectType(ua, isBot),
		Browser: formatBrowser(ua),
		OS:      formatOS(ua),
		IsBot:   isBot,
		Raw:     uaStr,
	}

	if clientInfo.IsBot {
		return fmt.Sprintf("%s(bot)|%s|%s|%s",
			clientInfo.Type,
			clientInfo.Browser,
			clientInfo.OS,
			clientInfo.Raw,
		)
	}

	return fmt.Sprintf("%s|%s|%s|%s",
		clientInfo.Type,
		clientInfo.Browser,
		clientInfo.OS,
		clientInfo.Raw,
	)
}

func detectType(ua *uasurfer.UserAgent, isBot bool) string {
	if isBot {
		return "bot"
	}

	switch ua.DeviceType {
	case uasurfer.DevicePhone, uasurfer.DeviceTablet:
		return "mobile"
	default:
		return "browser"
	}
}

func formatBrowser(ua *uasurfer.UserAgent) string {
	name := ua.Browser.Name.String()
	version := formatVersion(ua.Browser.Version)

	if name == "" {
		name = "unknown"
	}
	if version == "" {
		return name
	}

	return name + "_" + version
}
func formatVersion(v uasurfer.Version) string {
	if v.Major == 0 {
		return ""
	}

	if v.Patch != 0 {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}

	if v.Minor != 0 {
		return fmt.Sprintf("%d.%d", v.Major, v.Minor)
	}

	return fmt.Sprintf("%d", v.Major)
}

func formatOS(ua *uasurfer.UserAgent) string {
	os := ua.OS.Name.String()
	if os == "" {
		return "unknown"
	}
	return os
}

func isBotUA(ua string) bool {
	ua = strings.ToLower(ua)

	keywords := []string{
		"bot",
		"crawler",
		"spider",
		"slurp",
		"curl",
		"wget",
	}

	for _, k := range keywords {
		if strings.Contains(ua, k) {
			return true
		}
	}
	return false
}
