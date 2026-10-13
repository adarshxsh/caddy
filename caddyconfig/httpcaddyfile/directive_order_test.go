package httpcaddyfile

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestConcurrentAdaptationNoRace(t *testing.T) {
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			adapter := caddyfile.Adapter{
				ServerType: ServerType{},
			}
			input := fmt.Sprintf(`{
				order respond %s vars
			}
			example%d.com {
				vars x %d
				respond "hello"
			}`, func() string {
				if id%2 == 0 {
					return "before"
				}
				return "after"
			}(), id, id)

			_, _, err := adapter.Adapt([]byte(input), nil)
			if err != nil {
				t.Errorf("goroutine %d failed to adapt Caddyfile: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestSequentialAdaptationIsolation(t *testing.T) {
	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}

	// Caddyfile A modifies order: respond before vars
	caddyfileA := `{
		order respond before vars
	}
	example.com {
		vars x 1
		respond "hello"
	}`

	// Caddyfile B has default order (vars before respond)
	caddyfileB := `{
	}
	example.com {
		vars x 1
		respond "hello"
	}`

	outA, _, err := adapter.Adapt([]byte(caddyfileA), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile A: %v", err)
	}

	outB, _, err := adapter.Adapt([]byte(caddyfileB), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile B: %v", err)
	}

	handlersA := extractHandlersFromJSON(t, outA)
	handlersB := extractHandlersFromJSON(t, outB)

	if len(handlersA) < 2 || handlersA[0] != "static_response" {
		t.Errorf("expected static_response first in Caddyfile A, got %v", handlersA)
	}

	if len(handlersB) < 2 || handlersB[0] != "vars" {
		t.Errorf("expected vars first in Caddyfile B (baseline order), got %v", handlersB)
	}
}

type routeJSON struct {
	Match  []any       `json:"match,omitempty"`
	Handle []handleJSON `json:"handle,omitempty"`
}

type handleJSON struct {
	Handler string      `json:"handler"`
	Routes  []routeJSON `json:"routes,omitempty"`
}

func extractHandlersFromJSON(t *testing.T, out []byte) []string {
	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []routeJSON `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("unmarshaling config: %v", err)
	}

	var handlers []string
	var collectFromHandles func(handles []handleJSON)
	collectFromHandles = func(handles []handleJSON) {
		for _, h := range handles {
			if h.Handler != "" && h.Handler != "subroute" {
				handlers = append(handlers, h.Handler)
			}
			for _, r := range h.Routes {
				collectFromHandles(r.Handle)
			}
		}
	}

	for _, srv := range config.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			collectFromHandles(r.Handle)
		}
	}
	return handlers
}

func TestConcurrentRegisterDirectiveOrder(t *testing.T) {
	var wg sync.WaitGroup
	const goroutines = 10
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			_ = defaultDirectiveOrderClone()
		}(i)
	}

	wg.Wait()
}
