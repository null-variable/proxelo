package compile

import (
	"slices"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"

	"github.com/null-variable/proxelo/internal/model"
)

// Standard params of each protocol, as nginx ships them in fastcgi.conf,
// uwsgi_params and scgi_params ($nginx_version reads "proxelo").
var (
	cgiParams = [][3]string{
		{"QUERY_STRING", "$query_string"},
		{"REQUEST_METHOD", "$request_method"},
		{"CONTENT_TYPE", "$content_type"},
		{"CONTENT_LENGTH", "$content_length"},
	}
	fastcgiParams = slices.Concat([][3]string{
		{"SCRIPT_FILENAME", "$document_root$fastcgi_script_name"},
	}, cgiParams, [][3]string{
		{"SCRIPT_NAME", "$fastcgi_script_name"},
		{"REQUEST_URI", "$request_uri"},
		{"DOCUMENT_URI", "$document_uri"},
		{"DOCUMENT_ROOT", "$document_root"},
		{"SERVER_PROTOCOL", "$server_protocol"},
		{"REQUEST_SCHEME", "$scheme"},
		{"HTTPS", "$https", "if_not_empty"},
		{"GATEWAY_INTERFACE", "CGI/1.1"},
		{"SERVER_SOFTWARE", "proxelo"},
		{"REMOTE_ADDR", "$remote_addr"},
		{"REMOTE_PORT", "$remote_port"},
		{"SERVER_ADDR", "$server_addr"},
		{"SERVER_PORT", "$server_port"},
		{"SERVER_NAME", "$server_name"},
		{"REDIRECT_STATUS", "200"},
	})
	uwsgiParams = slices.Concat(cgiParams, [][3]string{
		{"REQUEST_URI", "$request_uri"},
		{"PATH_INFO", "$document_uri"},
		{"DOCUMENT_ROOT", "$document_root"},
		{"SERVER_PROTOCOL", "$server_protocol"},
		{"REQUEST_SCHEME", "$scheme"},
		{"HTTPS", "$https", "if_not_empty"},
		{"REMOTE_ADDR", "$remote_addr"},
		{"REMOTE_PORT", "$remote_port"},
		{"SERVER_PORT", "$server_port"},
		{"SERVER_NAME", "$server_name"},
	})
	// SCGI sends CONTENT_LENGTH itself, first.
	scgiParams = [][3]string{
		{"REQUEST_METHOD", "$request_method"},
		{"REQUEST_URI", "$request_uri"},
		{"QUERY_STRING", "$query_string"},
		{"CONTENT_TYPE", "$content_type"},
		{"DOCUMENT_URI", "$document_uri"},
		{"DOCUMENT_ROOT", "$document_root"},
		{"SCGI", "1"},
		{"SERVER_PROTOCOL", "$server_protocol"},
		{"REQUEST_SCHEME", "$scheme"},
		{"HTTPS", "$https", "if_not_empty"},
		{"REMOTE_ADDR", "$remote_addr"},
		{"REMOTE_PORT", "$remote_port"},
		{"SERVER_PORT", "$server_port"},
		{"SERVER_NAME", "$server_name"},
	}
)

var gatewayProtocols = map[model.GatewayProtocol]snapshotv1.GatewayAction_Protocol{
	model.GatewayFastCGI: snapshotv1.GatewayAction_PROTOCOL_FASTCGI,
	model.GatewayUwsgi:   snapshotv1.GatewayAction_PROTOCOL_UWSGI,
	model.GatewaySCGI:    snapshotv1.GatewayAction_PROTOCOL_SCGI,
}

// gateway compiles g: the protocol's standard params unless left out, then
// g's own, a param of the same name replacing the standard one in place.
// DefaultParams is the standard param set of a protocol, which every
// gateway sends unless NoDefaultParams.
func DefaultParams(p model.GatewayProtocol) []model.GatewayParam {
	std := fastcgiParams
	switch p {
	case model.GatewayUwsgi:
		std = uwsgiParams
	case model.GatewaySCGI:
		std = scgiParams
	}
	out := make([]model.GatewayParam, len(std))
	for i, q := range std {
		out[i] = model.GatewayParam{Name: q[0], Value: q[1], IfNotEmpty: q[2] != ""}
	}
	return out
}

func gateway(g *model.GatewayAction, pa *snapshotv1.ProxyAction) *snapshotv1.GatewayAction {
	var params []*snapshotv1.GatewayParam
	if !g.NoDefaultParams {
		for _, p := range DefaultParams(g.Protocol) {
			params = append(params, &snapshotv1.GatewayParam{Name: p.Name, Value: p.Value, IfNotEmpty: p.IfNotEmpty})
		}
	}
	for _, p := range g.Params {
		out := &snapshotv1.GatewayParam{Name: p.Name, Value: p.Value, IfNotEmpty: p.IfNotEmpty}
		if i := slices.IndexFunc(params, func(q *snapshotv1.GatewayParam) bool { return q.Name == p.Name }); i >= 0 {
			params[i] = out
		} else {
			params = append(params, out)
		}
	}
	return &snapshotv1.GatewayAction{
		Protocol:           gatewayProtocols[g.Protocol],
		Proxy:              pa,
		Params:             params,
		PassRequestHeaders: !g.NoRequestHeaders,
		DocumentRoot:       g.DocumentRoot,
		Index:              g.Index,
		SplitPathInfo:      g.SplitPathInfo,
	}
}
