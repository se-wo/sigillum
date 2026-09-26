// Package crdcheck verifies at startup that the installed CRDs know the
// fields this binary relies on.
//
// Helm installs the chart's CRDs only on first install, so an upgrade that
// skips the manual CRD step runs new code against old schemas. The API
// server then prunes fields it does not know without an error (a
// server-side apply only warns), and a policy whose only recipient
// restriction is allowedRecipients would allow every domain that is not
// blocked. The check turns that into a failed rollout with a clear message.
//
// It reads the published OpenAPI v3 schemas, which every authenticated
// client may read (system:discovery), so it needs no RBAC.
package crdcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/openapi"
	"k8s.io/client-go/rest"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// Field is a schema property the running version depends on.
type Field struct {
	Kind string
	// Path is the property path below the object root.
	Path []string
}

func (f Field) String() string { return f.Kind + " " + strings.Join(f.Path, ".") }

// Required lists fields whose absence from an outdated CRD would loosen a
// restriction or lose state. Add a field here when a release introduces
// one like that; TestRequiredFieldsExistInCRDs keeps the list in sync with
// the generated CRDs.
var Required = []Field{
	// 0.3.0: without it a recipient allowlist is pruned to "allow all".
	{Kind: "MailPolicy", Path: []string{"spec", "recipientRestrictions", "allowedRecipients"}},
	// 0.3.0: new kind; the controller and SMTP proxy watch it.
	{Kind: "MailCredential", Path: []string{"spec", "serviceAccountName"}},
}

// UpgradeHint tells the operator how to fix an outdated schema.
const UpgradeHint = "apply the CRDs of this release before upgrading " +
	"(kubectl apply --server-side -f charts/sigillum/crds/), or set --skip-crd-check"

// Timeout bounds Wait at startup, below the liveness probe budgets.
const Timeout = 30 * time.Second

// SkipFlagUsage is the help text of every mode's --skip-crd-check flag.
const SkipFlagUsage = "do not verify at startup that the installed CRDs match this version (for clusters that hide the OpenAPI v3 endpoint)"

// Wait runs Verify until it succeeds or timeout elapses, since the API
// server publishes a created or updated CRD schema a few seconds late.
func Wait(ctx context.Context, cfg *rest.Config, fields []Field, timeout time.Duration) error {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		err = Verify(ctx, openapi.NewClientWithContext(dc.RESTClient()), fields)
		if err == nil {
			return nil
		}
		// Report what was missing, not the deadline cutting the last try.
		if ctx.Err() == nil || last == nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("installed CRDs do not match this version: %w; %s", last, UpgradeHint)
		case <-time.After(2 * time.Second):
		}
	}
}

// Verify checks that the served schemas contain every field.
func Verify(ctx context.Context, c openapi.ClientWithContext, fields []Field) error {
	gv := sigv1.GroupVersion
	paths, err := c.PathsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("read OpenAPI v3 discovery: %w", err)
	}
	p, ok := paths["apis/"+gv.Group+"/"+gv.Version]
	if !ok {
		return fmt.Errorf("no %s CRDs are installed", gv)
	}
	raw, err := p.SchemaWithContext(ctx, "application/json")
	if err != nil {
		return fmt.Errorf("read OpenAPI v3 schema of %s: %w", gv, err)
	}
	return verifyDoc(raw, fields)
}

type schema struct {
	Properties map[string]*schema `json:"properties"`
	GVK        []struct {
		Group   string `json:"group"`
		Version string `json:"version"`
		Kind    string `json:"kind"`
	} `json:"x-kubernetes-group-version-kind"`
}

func verifyDoc(raw []byte, fields []Field) error {
	var doc struct {
		Components struct {
			Schemas map[string]*schema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("decode OpenAPI v3 schema: %w", err)
	}
	gv := sigv1.GroupVersion
	kinds := map[string]*schema{}
	for _, s := range doc.Components.Schemas {
		for _, k := range s.GVK {
			if k.Group == gv.Group && k.Version == gv.Version {
				kinds[k.Kind] = s
			}
		}
	}
	var problems []string
	for _, f := range fields {
		s, ok := kinds[f.Kind]
		if !ok {
			problems = append(problems, fmt.Sprintf("kind %s is not installed", f.Kind))
			continue
		}
		for _, name := range f.Path {
			if s = s.Properties[name]; s == nil {
				problems = append(problems, fmt.Sprintf("the %s CRD has no field %s", f.Kind, strings.Join(f.Path, ".")))
				break
			}
		}
	}
	if len(problems) > 0 {
		// One line: it ends up in a single log record.
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}
