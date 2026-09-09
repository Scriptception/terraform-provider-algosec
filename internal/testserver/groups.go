// SPDX-License-Identifier: MPL-2.0
package testserver

// This standalone fixture is SYNTHETIC, not a recording or live acceptance server.
import (
	"encoding/json"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
)

type GroupsServer struct {
	*httptest.Server
	Mu                      sync.Mutex
	Groups                  map[string]client.DeviceGroup
	Calls                   []string
	Bodies                  [][]string
	ReadStatus, WriteStatus int
	ReadBody, WriteBody     string
	FailWrite               int
	WriteCount              int
	Noop                    bool
	AfterWrite              func(*GroupsServer)
	BeforeRead              func(*GroupsServer)
}

func SyntheticGroup(name string, members ...string) client.DeviceGroup {
	g := client.DeviceGroup{EntityType: "GROUP", Name: "internal:" + name, DisplayName: name, Firewalls: []client.GroupFirewall{}}
	for _, n := range members {
		g.Firewalls = append(g.Firewalls, client.GroupFirewall{EntityType: "FW_PIX", Name: "internal:" + n, DisplayName: n})
	}
	return g
}
func NewGroups() *GroupsServer {
	s := &GroupsServer{Groups: map[string]client.DeviceGroup{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}
func (s *GroupsServer) serve(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Calls = append(s.Calls, r.Method+" "+r.URL.EscapedPath())
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("PHPSESSID")
	if err != nil || cookie.Value != Session {
		w.WriteHeader(401)
		return
	}
	const base = "/afa/api/v1/groups"
	if r.Method == "GET" && r.URL.Path == base {
		if s.BeforeRead != nil {
			s.BeforeRead(s)
		}
		if s.ReadStatus != 0 {
			w.WriteHeader(s.ReadStatus)
			return
		}
		if s.ReadBody != "" {
			_, _ = w.Write([]byte(s.ReadBody))
			return
		}
		groups := []client.DeviceGroup{}
		for _, g := range s.Groups {
			groups = append(groups, g)
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i].DisplayName < groups[j].DisplayName })
		_ = json.NewEncoder(w).Encode(groups)
		return
	}
	s.WriteCount++
	var members []string
	if r.Body != nil && (r.Method == "POST" || strings.HasSuffix(r.URL.Path, "/removeDevices")) {
		if json.NewDecoder(r.Body).Decode(&members) != nil {
			w.WriteHeader(400)
			return
		}
	}
	s.Bodies = append(s.Bodies, members)
	if s.WriteStatus != 0 && (s.FailWrite == 0 || s.WriteCount == s.FailWrite) {
		w.WriteHeader(s.WriteStatus)
		_, _ = w.Write([]byte(`{"error":"synthetic-secret-must-not-leak"}`))
		return
	}
	if s.WriteBody != "" {
		_, _ = w.Write([]byte(s.WriteBody))
		return
	}
	if r.Method == "POST" && r.URL.Path == base {
		name := r.URL.Query().Get("displayName")
		if _, ok := s.Groups[name]; ok {
			w.WriteHeader(400)
			return
		}
		if !s.Noop {
			s.Groups[name] = SyntheticGroup(name, members...)
		}
		if s.AfterWrite != nil {
			s.AfterWrite(s)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Group created successfully."})
		return
	}
	tail := strings.TrimPrefix(r.URL.EscapedPath(), base+"/")
	action := ""
	for _, a := range []string{"addDevices", "removeDevices"} {
		if strings.HasSuffix(tail, "/"+a) {
			action = a
			tail = strings.TrimSuffix(tail, "/"+a)
		}
	}
	name, err := url.PathUnescape(tail)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	g, ok := s.Groups[name]
	if !ok {
		w.WriteHeader(404)
		return
	}
	message := "Group deleted successfully"
	if action == "" && r.Method == "DELETE" {
		if !s.Noop {
			delete(s.Groups, name)
		}
	} else {
		set := map[string]bool{}
		for _, n := range g.Members() {
			set[n] = true
		}
		if action == "addDevices" && r.Method == "POST" {
			for _, n := range members {
				set[n] = true
			}
			message = "Devices added successfully"
		} else if action == "removeDevices" && r.Method == "DELETE" {
			for _, n := range members {
				delete(set, n)
			}
			message = "Devices removed successfully"
		} else {
			w.WriteHeader(404)
			return
		}
		if len(set) == 0 {
			w.WriteHeader(400)
			return
		}
		all := []string{}
		for n := range set {
			all = append(all, n)
		}
		if !s.Noop {
			s.Groups[name] = SyntheticGroup(name, all...)
		}
	}
	if s.AfterWrite != nil {
		s.AfterWrite(s)
	}
	_ = json.NewEncoder(w).Encode(message)
}
