// Package doccheck holds repository-wide checks on documentation.
package doccheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const root = "../.."

// citedTest matches a test name as docs cite it. A subtest suffix after '/' is
// not part of the match.
var citedTest = regexp.MustCompile(`\bTest[A-Z]\w*`)

// TestCitedTestsExist fails when docs/design.md or a Go comment cites a test
// name that no test function declares.
func TestCitedTestsExist(t *testing.T) {
	fset := token.NewFileSet()
	declared := map[string]bool{}
	cited := map[string][]string{} // name -> where
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, "_test.go") {
				for _, decl := range f.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
						declared[fn.Name.Name] = true
					}
				}
			}
			for _, cg := range f.Comments {
				for _, name := range citedTest.FindAllString(cg.Text(), -1) {
					cited[name] = append(cited[name], fset.Position(cg.Pos()).String())
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	design, err := os.ReadFile(filepath.Join(root, "docs", "design.md"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(design), "\n") {
		for _, name := range citedTest.FindAllString(line, -1) {
			cited[name] = append(cited[name], "docs/design.md:"+strconv.Itoa(i+1))
		}
	}
	if len(declared) == 0 || len(cited) == 0 {
		t.Fatalf("found %d test funcs and %d cited names; the walk is broken", len(declared), len(cited))
	}
	for name, where := range cited {
		if !declared[name] {
			t.Errorf("%s cites %s, which no test declares", strings.Join(where, ", "), name)
		}
	}
	t.Logf("%d cited names, %d test funcs", len(cited), len(declared))
}
