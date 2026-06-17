package corplink

import (
	"fmt"
	"strings"
)

// URLGetCompany resolves a company code to its server domain. This endpoint
// lives on the shared corplink/volcengine host, not the per-company server.
const URLGetCompany = "https://corplink.volcengine.cn/api/match"

// The os / os_version query params are sent on every per-company request,
// mirroring the official Android client.
const (
	apiOS        = "Android"
	apiOSVersion = "2"
	userAgent    = "CorpLink/201000 (GooglePixel; Android 10; en)"
)

// apiName enumerates the per-company API endpoints.
type apiName int

const (
	apiLoginMethod apiName = iota
	apiTpsLoginMethod
	apiTpsTokenCheck
	apiCorplinkLoginMethod
	apiRequestEmailCode
	apiLoginEmail
	apiLoginPassword
	apiLoginPasswordV1
	apiListVPN
	apiPingVPN
	apiConnectVPN
	apiKeepAliveVPN
	apiDisconnectVPN
	apiOtp
	apiLogout
)

// apiTemplates maps each endpoint to its URL template. {{url}} is the server
// base (or VPN node base for the data-plane endpoints), {{os}}/{{version}} the
// device params.
var apiTemplates = map[apiName]string{
	apiLoginMethod:         "{{url}}/api/login/setting?os={{os}}&os_version={{version}}",
	apiTpsLoginMethod:      "{{url}}/api/tpslogin/link?os={{os}}&os_version={{version}}",
	apiTpsTokenCheck:       "{{url}}/api/tpslogin/token/check?os={{os}}&os_version={{version}}",
	apiCorplinkLoginMethod: "{{url}}/api/lookup?os={{os}}&os_version={{version}}",
	apiRequestEmailCode:    "{{url}}/api/login/code/send?os={{os}}&os_version={{version}}",
	apiLoginEmail:          "{{url}}/api/login/code/verify?os={{os}}&os_version={{version}}",
	apiLoginPassword:       "{{url}}/api/login?os={{os}}&os_version={{version}}",
	apiLoginPasswordV1:     "{{url}}/api/v1/login?os={{os}}&os_version={{version}}&client_source=FeiLian",
	apiListVPN:             "{{url}}/api/vpn/list?os={{os}}&os_version={{version}}",
	apiPingVPN:             "{{url}}/vpn/ping?os={{os}}&os_version={{version}}",
	apiConnectVPN:          "{{url}}/vpn/conn?os={{os}}&os_version={{version}}",
	apiKeepAliveVPN:        "{{url}}/vpn/report?os={{os}}&os_version={{version}}",
	apiDisconnectVPN:       "{{url}}/vpn/report?os={{os}}&os_version={{version}}",
	apiOtp:                 "{{url}}/api/v2/p/otp?os={{os}}&os_version={{version}}",
	apiLogout:              "{{url}}/api/logout?os={{os}}&os_version={{version}}&logout_all=false",
}

// isVPNScoped reports whether the endpoint is served by the chosen VPN node
// (data-plane) rather than the company server (control-plane).
func (a apiName) isVPNScoped() bool {
	switch a {
	case apiPingVPN, apiConnectVPN, apiKeepAliveVPN, apiDisconnectVPN:
		return true
	default:
		return false
	}
}

// renderURL substitutes the template variables for the given base url.
func (a apiName) renderURL(base string) string {
	t := apiTemplates[a]
	r := strings.NewReplacer(
		"{{url}}", strings.TrimRight(base, "/"),
		"{{os}}", apiOS,
		"{{version}}", apiOSVersion,
	)
	return r.Replace(t)
}

func (a apiName) String() string {
	if t, ok := apiTemplates[a]; ok {
		return fmt.Sprintf("api(%s)", t)
	}
	return "api(unknown)"
}
