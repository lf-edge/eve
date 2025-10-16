// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"fmt"
	"testing"
)

const luaScript = `
	function isPillarGoFile(path)
		pattern = "^/?pkg/pillar/.*\.go$"
		return path:find(pattern) ~= nil
	end

	function match(lf, ld)
		print("path: " .. lf:Path() .. " col from: " .. ld.TypeOfLine["comment"][1].ColFrom)
		print("comment string: " .. ld:IsCommentString())
		print("is pillar: " .. tostring(isPillarGoFile(lf:Path())))
		return true
	end

	function exec()
		--os.execute("/bin/ls")
	end
`

func TestLUA(t *testing.T) {
	la := LuaLoad("TestLUA", luaScript)

	ld := LineDiff{
		Operation:  LineAdd,
		Line:       "\t// some comment",
		LineNumber: 0,
		TypeOfLine: map[string][]struct {
			ColFrom uint32
			ColTo   uint32
		}{
			"comment": {{
				ColFrom: 0,
				ColTo:   42,
			}},
		},
	}
	lineDiffMatch := la.MatchDiff("luaActions_test.go", ld)
	fmt.Printf("ret: %+v\n", lineDiffMatch)

	fmt.Println("--- execute ---")
	la.do([]ActionToDo{})
}
