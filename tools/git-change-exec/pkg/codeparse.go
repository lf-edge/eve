// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"context"
	"math"
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/dockerfile"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/lua"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/yaml"
)

type LineProperty map[string][]struct {
	ColFrom uint32
	ColTo   uint32
}

func (lp LineProperty) String() string {
	ret := ""

	for property := range lp {
		ret += property + " "
	}

	return ret
}

type lineProperties map[uint32]LineProperty

func Parse(path string, content string) lineProperties {
	var lang *sitter.Language

	ext := filepath.Ext(path)
	switch ext {
	case ".go":
		lang = golang.GetLanguage()
	case ".sh":
		lang = bash.GetLanguage()
	case ".cpp", ".c++", ".hpp":
		lang = cpp.GetLanguage()
	case ".c", ".h":
		lang = c.GetLanguage()
	case ".py":
		lang = python.GetLanguage()
	case ".lua":
		lang = lua.GetLanguage()
	case ".rust":
		lang = rust.GetLanguage()
	case ".yaml", ".yml":
		lang = yaml.GetLanguage()
	}

	if filepath.Base(path) == "Dockerfile" {
		lang = dockerfile.GetLanguage()
	}

	if lang == nil {
		return nil
	}

	lt := parseWithLang(lang, []byte(content))

	return lt
}

type parser struct {
	sourceCode []byte
	types      lineProperties
}

func (p *parser) setType(line uint32, colFrom, colTo uint32, ty string) {
	if p.types[line] == nil {
		p.types[line] = make(LineProperty)
	}

	if p.types[line][ty] == nil {
		p.types[line][ty] = make([]struct {
			ColFrom uint32
			ColTo   uint32
		}, 0)
	}
	p.types[line][ty] = append(p.types[line][ty], struct {
		ColFrom uint32
		ColTo   uint32
	}{
		ColFrom: colFrom,
		ColTo:   colTo,
	})
}

func parseWithLang(lang *sitter.Language, sourceCode []byte) lineProperties {
	p := parser{
		sourceCode: sourceCode,
		types:      lineProperties{},
	}
	parser := sitter.NewParser()
	parser.SetLanguage(lang)
	tree, err := parser.ParseCtx(context.Background(), nil, sourceCode)
	if err != nil {
		panic(err)
	}

	n := tree.RootNode()

	p.walk(n)

	return p.types
}

func (p *parser) walk(n *sitter.Node) {
	from := n.StartPoint().Row
	to := n.EndPoint().Row

	for i := from; i <= to; i++ {
		colFrom := uint32(0)
		colTo := uint32(math.MaxUint32)

		if i == from {
			colFrom = n.StartPoint().Column
		}
		if i == to {
			colTo = n.EndPoint().Column
		}
		p.setType(i, colFrom, colTo, n.Type())
	}

	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.NamedChild(i)
		if child == nil {
			continue
		}

		p.walk(child)
	}
}
