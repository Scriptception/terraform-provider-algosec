package provider

import (
	"encoding/json"
	"encoding/pem"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Execute the unchanged live helper in a child process, exclusively against a
// synthetic TLS server with a locally trusted certificate and synthetic session.
func TestBaselineLiveCleanupUnconfirmedCreate(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	cats := map[string]client.Category{}
	puts, deletes := 0, 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(client.Categories{Categories: cats})
		case "PUT":
			puts++
			var in client.Categories
			json.NewDecoder(r.Body).Decode(&in)
			// Concurrent actor creates the name; this operation supplies no acknowledgement.
			for name := range in.Categories {
				cats[name] = client.Category{URLs: map[string][]string{"other.example.invalid": {"198.51.100.9"}}}
			}
			w.Write([]byte(`{}`))
		case "DELETE":
			deletes++
			var names []string
			json.NewDecoder(r.Body).Decode(&names)
			for _, name := range names {
				delete(cats, name)
			}
			json.NewEncoder(w).Encode(client.Categories{Categories: cats})
		default:
			w.WriteHeader(500)
		}
	}))
	defer s.Close()
	cert := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestAccURLCategoryMutation$", "-test.v")
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "ALGOSEC_") && !strings.HasPrefix(v, "TF_ACC=") && !strings.HasPrefix(v, "SSL_CERT_FILE=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "TF_ACC=1", "ALGOSEC_ACC_MUTATION=1", "ALGOSEC_ACC_DISPOSABLE=1", "ALGOSEC_URL="+s.URL, "ALGOSEC_SESSION_ID=synthetic", "SSL_CERT_FILE="+cert)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("unconfirmed create unexpectedly succeeded")
	}
	if !strings.Contains(string(output), "Category create not confirmed") {
		t.Fatalf("fixture did not reach ownership rejection: %s", output)
	}
	mu.Lock()
	defer mu.Unlock()
	if puts != 1 {
		t.Fatalf("expected one unconfirmed create, got %d: %s", puts, output)
	}
	if deletes != 0 {
		t.Fatalf("unchanged live cleanup deleted unowned concurrent category: puts=%d deletes=%d remaining=%d", puts, deletes, len(cats))
	}
}
