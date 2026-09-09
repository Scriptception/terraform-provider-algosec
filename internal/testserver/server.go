// SPDX-License-Identifier: MPL-2.0
// Package testserver contains SYNTHETIC fixtures based on the public A32.60 docs.
// This is not an appliance emulator or evidence of live API compatibility.
package testserver

import (
	"encoding/json"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

const Session = "syntheticSession123"

type Server struct {
	*httptest.Server
	Mu             sync.Mutex
	Categories     map[string]client.Category
	Devices        map[string]client.Device
	Writes, Logins int
	FailReads      bool
	NoopDelete     bool
}

func New() *Server {
	s := &Server{Categories: map[string]client.Category{}, Devices: map[string]client.Device{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	return s
}
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/fa/server/connection/login" && r.Method == "POST" {
		s.Logins++
		reply(map[string]any{"status": true, "SessionID": Session})
		return
	}
	cookie, err := r.Cookie("PHPSESSID")
	if err != nil || cookie.Value != Session {
		w.WriteHeader(403)
		reply(map[string]string{"message": "synthetic auth failure"})
		return
	}
	if r.Method == "GET" && s.FailReads {
		w.WriteHeader(503)
		reply(map[string]string{"error": "synthetic failure"})
		return
	}
	if r.Method != "GET" {
		s.Writes++
	}
	const cats = "/afa/api/v1/plugins/panorama/URLCategory/"
	if r.URL.Path == cats {
		switch r.Method {
		case "GET":
			reply(client.Categories{Categories: s.Categories})
			return
		case "PUT":
			var in client.Categories
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Categories == nil {
				w.WriteHeader(400)
				return
			}
			for k, v := range in.Categories {
				s.Categories[k] = v
			}
			reply(client.Categories{Categories: s.Categories})
			return
		case "DELETE":
			var names []string
			if json.NewDecoder(r.Body).Decode(&names) != nil {
				w.WriteHeader(400)
				return
			}
			if !s.NoopDelete {
				for _, n := range names {
					delete(s.Categories, n)
				}
			}
			reply(client.Categories{Categories: s.Categories})
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, cats) && r.Method == "PUT" {
		old := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, cats), "/")
		v, ok := s.Categories[old]
		if !ok {
			w.WriteHeader(400)
			return
		}
		var name string
		if json.NewDecoder(r.Body).Decode(&name) != nil {
			w.WriteHeader(400)
			return
		}
		delete(s.Categories, old)
		s.Categories[name] = v
		reply(client.Categories{Categories: s.Categories})
		return
	}
	if strings.TrimSuffix(r.URL.Path, "/") == "/afa/api/v1/devices" {
		if r.Method == "GET" {
			out := []client.Device{}
			for _, v := range s.Devices {
				out = append(out, v)
			}
			reply(out)
			return
		}
	}
	switch r.URL.Path {
	case "/afa/api/v1/risks/profiles":
		reply([]string{"ExampleRiskProfile"})
		return
	case "/afa/api/v1/security_zones/get_profiles_list":
		reply([]string{"example.xlsx"})
		return
	case "/afa/api/v1/security_zones/example.xlsx/get_zones":
		reply([]client.SecurityZone{{Name: "ExampleZone", Addresses: []string{"192.0.2.0/24"}}})
		return
	case "/afa/api/v1/deviceZones":
		reply(map[string]any{"deviceZones": []client.DeviceZone{{Name: "ExampleZone", DeviceName: "ExampleDevice", Interfaces: []string{"eth0"}, IPAddress: "192.0.2.0/24"}}, "additionalInformation": []string{}})
		return
	case "/afa/api/v1/networkObject/search/findByOriginalNameContaining":
		reply(map[string]any{"content": []client.NetworkObject{{ID: 1, CanonizedName: "ExampleObject", OriginalName: "ExampleObject", IPAddress: "192.0.2.0/24", IPType: "IPv4"}}, "last": true, "number": 0, "totalPages": 1, "totalElements": 1})
		return
	case "/afa/api/v1/trustedTraffic/firewalls/ExampleDevice":
		b := false
		reply(map[string]any{"content": []client.TrustedTraffic{{ID: 1, Source: "192.0.2.1", Destination: "198.51.100.1", Service: "https", DisplayTrafficLevel: "ExampleDevice", TrustFutureChanges: &b}}, "last": true, "number": 0, "totalPages": 1, "totalElements": 1})
		return
	}
	w.WriteHeader(404)
	reply(map[string]string{"error": "no synthetic contract for this path"})
}
