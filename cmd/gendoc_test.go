package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func docEngine() *gin.Engine {
	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/auth/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/auth/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// TestMarkdownRoutesDocShape pins the document the hand rolled generator produces in place of
// the source framework's route documentation generator, which has no gin equivalent. The route
// count line and the collapsible blocks are
// the parts a reader of routes.md actually consumes.
func TestMarkdownRoutesDocShape(t *testing.T) {
	doc := markdownRoutesDoc(docEngine(), "github.com/dhax/go-base", "GoBase REST API.")

	if !strings.HasPrefix(doc, "# github.com/dhax/go-base\n\nGoBase REST API.\n\n## Routes\n\n") {
		t.Errorf("header: unexpected prefix in %q", doc[:min(len(doc), 120)])
	}
	if !strings.HasSuffix(doc, "\nTotal # of routes: 3\n") {
		t.Errorf("footer: want a route count of 3, got %q", doc[max(0, len(doc)-40):])
	}
	if got := strings.Count(doc, "<details>"); got != 3 {
		t.Errorf("details blocks: want 3, got %d", got)
	}
	for _, want := range []string{
		"<summary>`/auth/login`</summary>",
		"- **/auth/login**",
		"\t- _GET_\n",
		"\t- _POST_\n",
		"<summary>`/healthz`</summary>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("document is missing %q", want)
		}
	}
}

// TestMarkdownRoutesDocIsSorted pins deterministic output: an unsorted walk of the gin trees
// produces a different file on every run and makes routes.md churn in diffs.
func TestMarkdownRoutesDocIsSorted(t *testing.T) {
	doc := markdownRoutesDoc(docEngine(), "p", "i")

	healthz := strings.Index(doc, "<summary>`/healthz`</summary>")
	login := strings.Index(doc, "<summary>`/auth/login`</summary>")
	if login < 0 || healthz < 0 {
		t.Fatalf("both routes should be present, got %q", doc)
	}
	if login > healthz {
		t.Error("routes: want /auth/login before /healthz")
	}

	get := strings.Index(doc, "\t- _GET_\n")
	post := strings.Index(doc, "\t- _POST_\n")
	if get > post {
		t.Error("methods on the same path: want GET before POST")
	}
}

// TestHandlerNameTrimsModulePath pins that handler labels stay readable, as docgen's did.
func TestHandlerNameTrimsModulePath(t *testing.T) {
	got := handlerName("github.com/dhax/go-base/api/admin.(*AccountResource).list-fm")
	if strings.HasPrefix(got, "github.com/dhax/go-base/") {
		t.Errorf("handler name: want the module prefix trimmed, got %q", got)
	}
	if !strings.Contains(got, "list") {
		t.Errorf("handler name: want the method retained, got %q", got)
	}
}

// TestHandlerSourceLocatesFile pins the source links in the generated document.
func TestHandlerSourceLocatesFile(t *testing.T) {
	got := handlerSource(func(c *gin.Context) {})
	if !strings.Contains(got, "gendoc_test.go#L") {
		t.Errorf("handler source: want a file and line reference to this test file, got %q", got)
	}
}
