package httpcaddyfile_test

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func TestInstanceScopedDirectiveOrder(t *testing.T) {
	caddyfileA := `{
		order respond before header
	}
	example.com {
		header /foo X-Test "A"
		respond /foo "Hello"
	}`

	caddyfileB := `example.com {
		header /foo X-Test "B"
		respond /foo "World"
	}`

	adapter := caddyfile.Adapter{
		ServerType: httpcaddyfile.ServerType{},
	}

	// Adapt Caddyfile A
	outA, _, err := adapter.Adapt([]byte(caddyfileA), nil)
	if err != nil {
		t.Fatalf("adapting caddyfile A: %v", err)
	}

	// Adapt Caddyfile B
	outB, _, err := adapter.Adapt([]byte(caddyfileB), nil)
	if err != nil {
		t.Fatalf("adapting caddyfile B: %v", err)
	}

	type jsonConfig struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handlers []struct {
							Handler string `json:"handler"`
							Routes  []struct {
								Handlers []struct {
									Handler string `json:"handler"`
								} `json:"handle"`
							} `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	var cfgA, cfgB jsonConfig
	if err := json.Unmarshal(outA, &cfgA); err != nil {
		t.Fatalf("unmarshaling cfgA: %v", err)
	}
	if err := json.Unmarshal(outB, &cfgB); err != nil {
		t.Fatalf("unmarshaling cfgB: %v", err)
	}

	srvA, ok := cfgA.Apps.HTTP.Servers["srv0"]
	if !ok || len(srvA.Routes) < 1 || len(srvA.Routes[0].Handlers) < 1 || len(srvA.Routes[0].Handlers[0].Routes) < 1 || len(srvA.Routes[0].Handlers[0].Routes[0].Handlers) < 2 {
		t.Fatalf("unexpected structure for cfgA: %s", string(outA))
	}

	// In Caddyfile A, order was: respond before header
	handlersA := srvA.Routes[0].Handlers[0].Routes[0].Handlers
	h0A := handlersA[0].Handler
	h1A := handlersA[1].Handler
	if h0A != "static_response" || h1A != "headers" {
		t.Errorf("Caddyfile A expected respond then headers, got %s then %s", h0A, h1A)
	}

	srvB, ok := cfgB.Apps.HTTP.Servers["srv0"]
	if !ok || len(srvB.Routes) < 1 || len(srvB.Routes[0].Handlers) < 1 || len(srvB.Routes[0].Handlers[0].Routes) < 1 || len(srvB.Routes[0].Handlers[0].Routes[0].Handlers) < 2 {
		t.Fatalf("unexpected structure for cfgB: %s", string(outB))
	}

	// In Caddyfile B, standard order applies: header before respond
	handlersB := srvB.Routes[0].Handlers[0].Routes[0].Handlers
	h0B := handlersB[0].Handler
	h1B := handlersB[1].Handler
	if h0B != "headers" || h1B != "static_response" {
		t.Errorf("Caddyfile B expected headers then respond, got %s then %s", h0B, h1B)
	}
}

func TestConcurrentAdaptationsRace(t *testing.T) {
	caddyfileA := `{
		order respond before header
	}
	example.com {
		header /foo X-Test "A"
		respond /foo "Hello"
	}`

	caddyfileB := `example.com {
		header /foo X-Test "B"
		respond /foo "World"
	}`

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
			_, _, err := adapter.Adapt([]byte(caddyfileA), nil)
			if err != nil {
				t.Errorf("concurrent adapt A error: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
			_, _, err := adapter.Adapt([]byte(caddyfileB), nil)
			if err != nil {
				t.Errorf("concurrent adapt B error: %v", err)
			}
		}()
	}
	wg.Wait()
}
