// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
)

const upgradeAddress = "registry.terraform.io/scriptception/algosec"

// This test never downloads providers or contacts an appliance. It is optional
// because the immutable published archive is deliberately not vendored.
func TestPublishedUpgrade(t *testing.T) {
	archive, digest, evidence := os.Getenv("ALGOSEC_UPGRADE_OLD_ARCHIVE"), os.Getenv("ALGOSEC_UPGRADE_OLD_SHA256"), os.Getenv("ALGOSEC_UPGRADE_EVIDENCE")
	if archive == "" && digest == "" && evidence == "" {
		t.Skip("published-state upgrade NOT run: set ALGOSEC_UPGRADE_OLD_ARCHIVE, ALGOSEC_UPGRADE_OLD_SHA256, ALGOSEC_UPGRADE_EVIDENCE and TF_ACC_TERRAFORM_PATH; see docs/published-upgrade.md")
	}
	if archive == "" || digest == "" || evidence == "" || os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		t.Fatal("all four published upgrade inputs are required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("published upgrade currently requires linux_amd64")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = filepath.Abs(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if evidence == root || strings.HasPrefix(evidence, root+string(os.PathSeparator)) {
		t.Fatal("evidence must be outside the repository")
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	work, err := os.MkdirTemp(evidence, "run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic upgrade evidence: %s", work)
	scratch, err := os.MkdirTemp(os.Getenv("ALGOSEC_UPGRADE_SCRATCH"), "algosec-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratch)
	h := &upgradeCLI{t: t, work: work, terraform: os.Getenv("TF_ACC_TERRAFORM_PATH")}
	h.env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + work, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "TF_INPUT=0", "TF_DATA_DIR=" + filepath.Join(scratch, "terraform-data")}
	// No ambient credentials, CLI arguments, reattach, caches, proxies or logging.
	old, err := upgradeArchive(archive, digest, "0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(scratch, "old-binary")
	h.write(oldPath, old, 0700)
	if err := upgradeBinaryVersion(oldPath, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(work, "old-archive.sha256"), []byte(digest+"\n"), 0600)
	h.write(filepath.Join(work, "old-binary.sha256"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(old))), 0600)
	versionBytes, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(versionBytes))
	if version == "0.2.0" || version == "" {
		t.Fatal("candidate VERSION must differ from published 0.2.0")
	}
	candidate := filepath.Join(scratch, "candidate-binary")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-X main.version="+version, "-o", candidate, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	newBinary, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(work, "candidate-binary.sha256"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(newBinary))), 0600)
	source := exec.Command("git", "status", "--short")
	source.Dir = root
	status, err := source.Output()
	if err != nil {
		t.Fatal(err)
	}
	source = exec.Command("git", "rev-parse", "HEAD")
	source.Dir = root
	head, err := source.Output()
	if err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(work, "source.txt"), append(head, status...), 0600)
	mirror := filepath.Join(scratch, "mirror", upgradeAddress)
	if err := os.MkdirAll(mirror, 0700); err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(mirror, "terraform-provider-algosec_0.2.0_linux_amd64.zip"), mustUpgradeRead(t, archive), 0600)
	h.pack(filepath.Join(mirror, "terraform-provider-algosec_"+version+"_linux_amd64.zip"), "terraform-provider-algosec_v"+version, newBinary)
	cli := filepath.Join(work, "testing.tfrc")
	h.write(cli, []byte(fmt.Sprintf("provider_installation {\n filesystem_mirror {\n path = %q\n include = [%q]\n }\n}\n", filepath.Join(scratch, "mirror"), upgradeAddress)), 0600)
	h.env = append(h.env, "TF_CLI_CONFIG_FILE="+cli)
	h.run(0, "version", "-json")
	// Inspect actual installed binaries before any fixture exists or managed write.
	h.config("0.2.0", "")
	h.run(0, "init", "-backend=false", "-input=false", "-no-color")
	oldSchema := h.schema("old-schema.json")
	if err := upgradeSchema(oldSchema, oldSchema); err != nil {
		t.Fatal(err)
	}
	h.config(version, "")
	h.run(0, "init", "-upgrade", "-backend=false", "-input=false", "-no-color")
	newSchema := h.schema("candidate-schema.json")
	if err := upgradeSchema(oldSchema, newSchema); err != nil {
		t.Fatal(err)
	}
	// Real rejected inputs, through the same guards used by the functional path.
	t.Run("reject_checksum", func(t *testing.T) {
		if _, err := upgradeArchive(archive, strings.Repeat("0", 64), "0.2.0"); err == nil {
			t.Fatal("wrong checksum accepted")
		}
	})
	t.Run("reject_archive_version", func(t *testing.T) {
		if _, err := upgradeArchive(archive, digest, "0.1.4"); err == nil {
			t.Fatal("wrong archive version accepted")
		}
	})
	t.Run("reject_binary_version", func(t *testing.T) {
		if err := upgradeBinaryVersion(candidate, "v0.2.0"); err == nil {
			t.Fatal("candidate accepted as published version")
		}
	})
	t.Run("reject_schema", func(t *testing.T) {
		bad := map[string]upgradeResourceSchema{}
		for k, v := range oldSchema {
			bad[k] = v
		}
		delete(bad, "algosec_trusted_rule")
		if err := upgradeSchema(bad, newSchema); err == nil {
			t.Fatal("missing old schema accepted")
		}
		b, _ := json.Marshal(newSchema)
		var changed map[string]upgradeResourceSchema
		json.Unmarshal(b, &changed)
		attr := changed["algosec_device_group"].Block.Attributes["id"]
		attr.Type = json.RawMessage(`"number"`)
		changed["algosec_device_group"].Block.Attributes["id"] = attr
		if err := upgradeSchema(oldSchema, changed); err == nil {
			t.Fatal("changed ID type accepted")
		}
	})
	if t.Failed() {
		t.Fatal("precondition regression failed before fixture start")
	}
	h.write(filepath.Join(work, "preconditions.json"), []byte(`{"rejected":["checksum","archive_version","binary_version","missing_schema","changed_id_type"],"managed_writes":0,"fixture_started":false}`), 0600)
	f := newUpgradeFixture(t)
	defer f.server.Close()
	defer f.categories.Close()
	defer f.groups.Close()
	ca := filepath.Join(work, "fixture-ca.pem")
	h.write(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0600)
	h.env = append(h.env, "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+filepath.Join(work, "empty-ca-dir"), "ALGOSEC_SESSION_ID="+testserver.Session)
	body := fmt.Sprintf(`provider "algosec" {
 url = %q
 insecure = false
 read_only = false
 experimental_device_groups = true
 experimental_trusted_rules = true
}
resource "algosec_device_group" "test" {
 display_name = "Upgrade /雪?%%"
 members = ["Member A", "Member B"]
}
resource "algosec_url_category" "test" {
 name = "Upgrade /雪?%%"
 urls = { "service.example.invalid" = ["192.0.2.1", "2001:db8::1"] }
}
resource "algosec_trusted_rule" "test" {
 device_name = "Device /雪?%%+#"
 rule_id = "Rule /雪?%%+#,"
 comment = "Owned synthetic metadata"
 expiration_date = "2099-12-31"
}
`, f.server.URL)
	h.config("0.2.0", body)
	h.run(0, "init", "-upgrade", "-backend=false", "-input=false", "-no-color")
	h.run(0, "apply", "-auto-approve", "-input=false", "-no-color")
	h.write(filepath.Join(work, "published-main.tf.txt"), mustUpgradeRead(t, filepath.Join(work, "main.tf")), 0600)
	h.write(filepath.Join(work, "published-lock.hcl"), mustUpgradeRead(t, filepath.Join(work, ".terraform.lock.hcl")), 0600)
	oldState := mustUpgradeRead(t, filepath.Join(work, "terraform.tfstate"))
	h.write(filepath.Join(work, "published-state.tfstate"), oldState, 0600)
	h.write(filepath.Join(work, "published-state.sha256"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(oldState))), 0600)
	oldValues := h.values("published-values.json")
	if len(oldValues) != 3 {
		t.Fatalf("old binary created %d resources, want 3", len(oldValues))
	}
	expected := map[string]string{"algosec_device_group.test": "Upgrade /雪?%", "algosec_url_category.test": "Upgrade /雪?%", "algosec_trusted_rule.test": trustedID("Device /雪?%+#", "Rule /雪?%+#,")}
	for address, id := range expected {
		if oldValues[address]["id"] != id {
			t.Fatalf("unexpected published ID for %s", address)
		}
	}
	created := f.snapshot(h, "after-published-create")
	if created != 3 {
		t.Fatalf("published create mutations = %d, want exactly 3", created)
	}
	// Preserve the very same state, fixture and resource HCL. Only the pin changes.
	h.config(version, body)
	h.run(0, "init", "-upgrade", "-backend=false", "-input=false", "-no-color")
	if !reflect.DeepEqual(oldState, mustUpgradeRead(t, filepath.Join(work, "terraform.tfstate"))) {
		t.Fatal("re-init modified preserved published state")
	}
	h.write(filepath.Join(work, "candidate-lock.hcl"), mustUpgradeRead(t, filepath.Join(work, ".terraform.lock.hcl")), 0600)
	h.plan("upgrade", 0, nil)
	h.run(0, "apply", "-refresh-only", "-auto-approve", "-input=false", "-no-color")
	newValues := h.values("upgraded-values.json")
	for address, attrs := range oldValues {
		for key, value := range attrs {
			if !reflect.DeepEqual(value, newValues[address][key]) {
				t.Fatalf("upgrade changed %s.%s", address, key)
			}
		}
	}
	if f.snapshot(h, "after-upgrade-refresh") != created {
		t.Fatal("upgrade/refresh performed managed mutation")
	}
	h.plan("normal-read", 0, nil)
	if f.snapshot(h, "after-normal-read") != created {
		t.Fatal("normal read performed managed mutation")
	}
	f.drift()
	h.plan("controlled-drift", 2, map[string][]string{"algosec_device_group.test": {"update"}, "algosec_url_category.test": {"delete", "create"}, "algosec_trusted_rule.test": {"delete", "create"}})
	if f.snapshot(h, "after-drift-plan") != created {
		t.Fatal("drift plan performed managed mutation")
	}
	h.run(0, "apply", "-auto-approve", "-input=false", "-no-color", "controlled-drift.tfplan")
	reconciled := h.values("reconciled-values.json")
	for address, attrs := range oldValues {
		for key, value := range attrs {
			if !reflect.DeepEqual(value, reconciled[address][key]) {
				t.Fatalf("reconciliation changed owned value %s.%s", address, key)
			}
		}
	}
	if f.snapshot(h, "after-reconciliation") != created+6 {
		t.Fatal("expected group add/remove, category delete/create, trusted delete/create")
	}
	h.plan("reconciled", 0, nil)
	h.run(0, "destroy", "-auto-approve", "-input=false", "-no-color")
	if f.snapshot(h, "after-destroy") != created+9 {
		t.Fatal("cleanup did not perform exactly three managed deletes")
	}
	if len(h.values("destroyed-values.json")) != 0 {
		t.Fatal("destroy left managed state")
	}
	f.checkSentinels(t)
	h.write(filepath.Join(work, "PASS"), []byte("Synthetic published 0.2.0 preserved-state upgrade, drift reconciliation and exact owned cleanup passed. No live acceptance.\n"), 0600)
}

func upgradeArchive(path, digest, version string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(digest) != 64 || fmt.Sprintf("%x", sha256.Sum256(b)) != digest {
		return nil, fmt.Errorf("published archive SHA256 mismatch")
	}
	if filepath.Base(path) != "terraform-provider-algosec_"+version+"_linux_amd64.zip" {
		return nil, fmt.Errorf("published archive version/name mismatch")
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	var binary []byte
	for _, f := range z.File {
		if f.Name == "terraform-provider-algosec_v"+version {
			if binary != nil || f.UncompressedSize64 > 200<<20 {
				return nil, fmt.Errorf("invalid binary member")
			}
			r, e := f.Open()
			if e != nil {
				return nil, e
			}
			binary, e = io.ReadAll(io.LimitReader(r, 200<<20))
			r.Close()
			if e != nil {
				return nil, e
			}
		}
	}
	if len(binary) == 0 {
		return nil, fmt.Errorf("published binary member missing")
	}
	return binary, nil
}
func upgradeBinaryVersion(path, version string) error {
	b, e := buildinfo.ReadFile(path)
	if e != nil {
		return e
	}
	if b.Main.Path != "github.com/Scriptception/terraform-provider-algosec" || b.Main.Version != version {
		return fmt.Errorf("published binary embedded module/version mismatch")
	}
	return nil
}

type upgradeAttribute struct {
	Type   json.RawMessage `json:"type"`
	Nested json.RawMessage `json:"nested_type"`
}
type upgradeResourceSchema struct {
	Version int `json:"version"`
	Block   struct {
		Attributes map[string]upgradeAttribute `json:"attributes"`
	} `json:"block"`
}

func upgradeSchema(old, new map[string]upgradeResourceSchema) error {
	expected := map[string]map[string]string{
		"algosec_device_group": {"id": `"string"`, "display_name": `"string"`, "internal_name": `"string"`, "members": `["set","string"]`},
		"algosec_url_category": {"id": `"string"`, "name": `"string"`, "urls": `["map",["set","string"]]`},
		"algosec_trusted_rule": {"id": `"string"`, "device_name": `"string"`, "rule_id": `"string"`, "comment": `"string"`, "expiration_date": `"string"`},
	}
	if len(old) != 3 {
		return fmt.Errorf("published schema must contain exactly three resources")
	}
	for name, attrs := range expected {
		o, ok := old[name]
		if !ok || o.Version != 0 || len(o.Block.Attributes) != len(attrs) {
			return fmt.Errorf("unexpected published schema %s", name)
		}
		n, ok := new[name]
		if !ok {
			return fmt.Errorf("candidate missing %s", name)
		}
		for key, typ := range attrs {
			a, ok := o.Block.Attributes[key]
			if !ok || string(a.Type) != typ {
				return fmt.Errorf("published type mismatch %s.%s", name, key)
			}
			b, ok := n.Block.Attributes[key]
			if !ok || !reflect.DeepEqual(a, b) {
				return fmt.Errorf("candidate type mismatch %s.%s", name, key)
			}
		}
	}
	return nil
}

type upgradeCLI struct {
	t               *testing.T
	work, terraform string
	env             []string
	sequence        int
}

func (h *upgradeCLI) write(path string, b []byte, mode os.FileMode) {
	h.t.Helper()
	if e := os.WriteFile(path, b, mode); e != nil {
		h.t.Fatal(e)
	}
}
func mustUpgradeRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (h *upgradeCLI) pack(path, name string, b []byte) {
	f, e := os.Create(path)
	if e != nil {
		h.t.Fatal(e)
	}
	z := zip.NewWriter(f)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0755)
	w, e := z.CreateHeader(header)
	if e != nil {
		h.t.Fatal(e)
	}
	if _, e = w.Write(b); e != nil {
		h.t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		h.t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		h.t.Fatal(e)
	}
}
func (h *upgradeCLI) config(version, body string) {
	h.write(filepath.Join(h.work, "main.tf"), []byte(fmt.Sprintf("terraform {\n required_providers {\n algosec = { source = %q, version = %q }\n }\n}\n", upgradeAddress, "= "+version)+body), 0600)
}
func (h *upgradeCLI) run(want int, args ...string) []byte {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.terraform, args...)
	cmd.Dir = h.work
	cmd.Env = h.env
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else {
			h.t.Fatal(err)
		}
	}
	h.sequence++
	h.write(filepath.Join(h.work, fmt.Sprintf("%02d-%s.log", h.sequence, args[0])), append([]byte(strings.Join(args, " ")+fmt.Sprintf("\nexit=%d\n", code)), out...), 0600)
	if code != want {
		h.t.Fatalf("terraform %v exit %d (want %d); see %s", args, code, want, h.work)
	}
	return out
}
func (h *upgradeCLI) schema(name string) map[string]upgradeResourceSchema {
	b := h.run(0, "providers", "schema", "-json")
	h.write(filepath.Join(h.work, name), b, 0600)
	var out struct {
		Providers map[string]struct {
			Resources map[string]upgradeResourceSchema `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	if e := json.Unmarshal(b, &out); e != nil {
		h.t.Fatal(e)
	}
	return out.Providers[upgradeAddress].Resources
}
func (h *upgradeCLI) values(name string) map[string]map[string]any {
	b := h.run(0, "show", "-json")
	h.write(filepath.Join(h.work, name), b, 0600)
	var out struct {
		Values struct {
			Root struct {
				Resources []struct {
					Address string
					Values  map[string]any
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"values"`
	}
	if e := json.Unmarshal(b, &out); e != nil {
		h.t.Fatal(e)
	}
	values := map[string]map[string]any{}
	for _, r := range out.Values.Root.Resources {
		values[r.Address] = r.Values
	}
	return values
}
func (h *upgradeCLI) plan(name string, code int, want map[string][]string) {
	h.run(code, "plan", "-input=false", "-no-color", "-detailed-exitcode", "-out="+name+".tfplan")
	b := h.run(0, "show", "-json", name+".tfplan")
	h.write(filepath.Join(h.work, name+"-plan.json"), b, 0600)
	var p struct {
		Changes []struct {
			Address string
			Change  struct{ Actions []string }
		} `json:"resource_changes"`
	}
	if e := json.Unmarshal(b, &p); e != nil {
		h.t.Fatal(e)
	}
	got := map[string][]string{}
	for _, c := range p.Changes {
		if !reflect.DeepEqual(c.Change.Actions, []string{"no-op"}) {
			got[c.Address] = c.Change.Actions
		}
	}
	if len(got) != len(want) {
		h.t.Fatalf("%s unexpected changes: %v", name, got)
	}
	for k, v := range want {
		if !reflect.DeepEqual(v, got[k]) {
			h.t.Fatalf("%s action mismatch %s: %v", name, k, got[k])
		}
	}
}

// Reuse the existing lifecycle handlers behind one TLS origin. Only method/path
// events are recorded; authentication headers and bodies are never logged.
type upgradeFixture struct {
	server     *httptest.Server
	categories *testserver.Server
	groups     *testserver.GroupsServer
	mu         sync.Mutex
	rules      map[string]client.TrustedRule
	events     []string
	writes     int
}

func newUpgradeFixture(t *testing.T) *upgradeFixture {
	f := &upgradeFixture{categories: testserver.New(), groups: testserver.NewGroups(), rules: map[string]client.TrustedRule{"unowned": {RuleID: "unowned", Comment: "keep", ExpirationDate: ""}}}
	f.categories.Categories["unowned"] = client.Category{URLs: map[string][]string{"unowned.example.invalid": {"198.51.100.1"}}}
	f.groups.Groups["unowned"] = testserver.SyntheticGroup("unowned", "keep")
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, r.Method+" "+r.URL.EscapedPath())
		if r.Method != "GET" {
			f.writes++
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/afa/api/v1/groups"):
			f.groups.Config.Handler.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/afa/api/v1/plugins/panorama/URLCategory/"):
			f.categories.Config.Handler.ServeHTTP(w, r)
		case r.URL.Path == "/afa/api/v1/trusted-rules/rules":
			cookie, e := r.Cookie("PHPSESSID")
			if e != nil || cookie.Value != testserver.Session {
				w.WriteHeader(403)
				return
			}
			reply := func(v any) {
				if e := json.NewEncoder(w).Encode(v); e != nil {
					t.Error(e)
				}
			}
			const device = "Device /雪?%+#"
			const rule = "Rule /雪?%+#,"
			switch r.Method {
			case "GET":
				if r.URL.Query().Get("deviceNames") != device {
					t.Error("unexpected trusted device query")
					w.WriteHeader(400)
					return
				}
				rules := []client.TrustedRule{f.rules["unowned"]}
				if v, ok := f.rules[rule]; ok {
					rules = append(rules, v)
				}
				reply([]any{map[string]any{"deviceName": device, "deviceId": "1", "deviceDisplayName": "Synthetic", "trustedRules": rules}})
			case "POST":
				var in struct {
					DeviceName string
					Rules      []struct{ ID, Comment, ExpirationDate string }
				}
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.DeviceName != device || len(in.Rules) != 1 || in.Rules[0].ID != rule {
					t.Error("unexpected trusted create ownership")
					w.WriteHeader(400)
					return
				}
				if _, ok := f.rules[rule]; ok {
					t.Error("overwrote existing trusted assignment")
					w.WriteHeader(409)
					return
				}
				f.rules[rule] = client.TrustedRule{RuleID: rule, Comment: in.Rules[0].Comment, ExpirationDate: in.Rules[0].ExpirationDate}
				reply(map[string]any{"trustedRuleIds": []string{rule}})
			case "DELETE":
				var in struct {
					DeviceName string
					RuleIDs    []string
				}
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.DeviceName != device || !reflect.DeepEqual(in.RuleIDs, []string{rule}) {
					t.Error("unexpected trusted deletion ownership")
					w.WriteHeader(400)
					return
				}
				delete(f.rules, rule)
				reply(map[string]any{"trustedRuleIds": []string{rule}})
			default:
				t.Error("unexpected trusted method")
				w.WriteHeader(405)
			}
		default:
			t.Error("unexpected fixture path")
			w.WriteHeader(404)
		}
	}))
	return f
}
func (f *upgradeFixture) snapshot(h *upgradeCLI, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups.Mu.Lock()
	defer f.groups.Mu.Unlock()
	f.categories.Mu.Lock()
	defer f.categories.Mu.Unlock()
	b, e := json.MarshalIndent(map[string]any{"synthetic": true, "managed_mutations": f.writes, "group_mutations": f.groups.WriteCount, "category_mutations": f.categories.Writes, "events": f.events, "groups": f.groups.Groups, "categories": f.categories.Categories, "trusted_rules": f.rules}, "", "  ")
	if e != nil {
		h.t.Fatal(e)
	}
	h.write(filepath.Join(h.work, name+".json"), b, 0600)
	return f.writes
}
func (f *upgradeFixture) drift() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups.Mu.Lock()
	defer f.groups.Mu.Unlock()
	f.categories.Mu.Lock()
	defer f.categories.Mu.Unlock()
	f.groups.Groups["Upgrade /雪?%"] = testserver.SyntheticGroup("Upgrade /雪?%", "Member A", "Drift")
	f.categories.Categories["Upgrade /雪?%"] = client.Category{URLs: map[string][]string{"service.example.invalid": {"192.0.2.99"}}}
	r := f.rules["Rule /雪?%+#,"]
	r.Comment = "controlled drift"
	f.rules[r.RuleID] = r
}
func (f *upgradeFixture) checkSentinels(t *testing.T) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups.Mu.Lock()
	defer f.groups.Mu.Unlock()
	f.categories.Mu.Lock()
	defer f.categories.Mu.Unlock()
	if !reflect.DeepEqual(f.groups.Groups, map[string]client.DeviceGroup{"unowned": testserver.SyntheticGroup("unowned", "keep")}) || !reflect.DeepEqual(f.categories.Categories, map[string]client.Category{"unowned": {URLs: map[string][]string{"unowned.example.invalid": {"198.51.100.1"}}}}) || !reflect.DeepEqual(f.rules, map[string]client.TrustedRule{"unowned": {RuleID: "unowned", Comment: "keep", ExpirationDate: ""}}) {
		t.Fatal("cleanup changed unowned sentinel or leaked owned object")
	}
}
