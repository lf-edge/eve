// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// DotExporter exports dependency graph into DOT [1].
// It provides two methods:
//  * Export(graph GraphR): export a single graph into DOT
//  * ExportTransition(src, dst GraphR): export graph "src" into DOT just
//    like with Export(), but additionally also describe what is out-of-sync
//    and will need a state transition to match the graph "dst".
//    For example, all items present in "dst" but missing in "src" are also
//    included, but with a lowered saturation for node fillcolor and with
//    a grey border.
//
// [1]: https://en.wikipedia.org/wiki/DOT_(graph_description_language)
type DotExporter struct {
	// CheckDeps : enable this option to have the dependencies checked
	// and edges colored accordingly (black vs. red).
	CheckDeps bool

	// Internal attributes used only during Export() and ExportTransition().
	graph      GraphR
	hueMap     map[string]float32 // item type -> fillcolor hue
	transition bool
	dstGraph   GraphR
}

const (
	indentChar = "\t"
)

// Export returns DOT description of the graph content. This can be visualized
// with Graphviz and used for troubleshooting/presentation purposes.
func (e *DotExporter) Export(graph GraphR) (dot string, err error) {
	e.graph = graph
	e.transition = false
	return e.export()
}

// ExportTransition exports graph "src" into DOT just like with Export(),
// but additionally also describes what is out-of-sync and will need a state
// transition to match the graph "dst".
func (e *DotExporter) ExportTransition(src, dst GraphR) (dot string, err error) {
	e.graph = src
	e.transition = true
	e.dstGraph = dst
	return e.export()
}

func (e *DotExporter) export() (dot string, err error) {
	e.hueMap = e.genHueMap()
	sb := strings.Builder{}
	_, err = sb.WriteString("digraph G {\n")
	if err != nil {
		return "", err
	}

	// Export subgraphs clusters starting with the implicit top-level one.
	err = e.exportSubgraph(&sb, SubGraphPath{})
	if err != nil {
		return "", err
	}

	err = e.exportEdges(&sb)
	if err != nil {
		return "", err
	}

	_, err = sb.WriteString("}\n")
	if err != nil {
		return "", err
	}
	return sb.String(), nil
}

func (e *DotExporter) exportSubgraph(w io.StringWriter, path SubGraphPath) error {
	var subG, dstSubG GraphR
	subG = GetSubGraphR(e.graph, path)
	if e.transition {
		dstSubG = GetSubGraphR(e.dstGraph, path)
	}

	// Determine indentation.
	var indent, nestedIndent string
	for i := 0; i < path.Len(); i++ {
		indent += indentChar
	}
	nestedIndent = indent + indentChar

	// output cluster header
	var name, description string
	if subG != nil {
		name = subG.Name()
		description = subG.Description()
	} else { // e.transition is true
		name = dstSubG.Name()
		description = dstSubG.Description()
	}
	if path.Len() > 0 {
		_, err := w.WriteString(fmt.Sprintf("%ssubgraph cluster_%s {\n",
			indent, escapeName(name)))
		if err != nil {
			return err
		}
	}

	// output graph attributes
	color := "black"
	if e.transition && subG == nil {
		color = "grey"
	}
	_, err := w.WriteString(fmt.Sprintf("%scolor = %s;\n",
		nestedIndent, color))
	if err != nil {
		return err
	}
	_, err = w.WriteString(fmt.Sprintf("%slabel = \"%s\";\n",
		nestedIndent, name))
	if err != nil {
		return err
	}
	_, err = w.WriteString(fmt.Sprintf("%stooltip = \"%s\";\n",
		nestedIndent, escapeTooltip(description)))
	if err != nil {
		return err
	}

	// output items
	if subG != nil {
		itemIter := subG.Items(false)
		for itemIter.Next() {
			item, state := itemIter.Item()
			err = e.exportItem(w, item, state, false, nestedIndent)
			if err != nil {
				return err
			}
		}
	}
	if e.transition {
		itemIter := dstSubG.Items(false)
		for itemIter.Next() {
			item, state := itemIter.Item()
			if e.graph != nil {
				if _, _, _, found := e.graph.Item(Reference(item)); found {
					continue
				}
			}
			err = e.exportItem(w, item, state, true, nestedIndent)
			if err != nil {
					return err
				}
		}
	}

	// output subgraphs
	if subG != nil {
		subGIter := subG.SubGraphs()
		for subGIter.Next() {
			nestedSubG := subGIter.SubGraph()
			err = e.exportSubgraph(w, path.Append(nestedSubG.Name()))
			if err != nil {
				return err
			}
		}
	}
	if e.transition && dstSubG != nil {
		subGIter := dstSubG.SubGraphs()
		for subGIter.Next() {
			nestedSubG := subGIter.SubGraph()
			if subG == nil || subG.SubGraph(nestedSubG.Name()) == nil {
				// Present in dst but missing in src.
				err = e.exportSubgraph(w, path.Append(nestedSubG.Name()))
				if err != nil {
					return err
				}
			}
		}
	}

	// closing cluster bracket
	if path.Len() > 0 {
		_, err = w.WriteString(indent + "}\n")
		if err != nil {
			return err
		}
	}
	return err
}

func (e *DotExporter) exportItem(w io.StringWriter, item Item, state ItemState,
	missing bool, indent string) (err error) {
	// Read the item state.
	var itemErr error
	var inTransition bool
	created := !missing
	if state != nil {
		itemErr = state.WithError()
		inTransition = state.InTransition()
		created = state.IsCreated()
	}
	// Choose color, shape and saturation based on the state.
	var (
		color      string
		saturation float32
		shape      string
	)
	if item.External() {
		shape = "doubleoctagon"
	} else {
		if inTransition {
			shape = "cds"
		} else {
			shape = "ellipse"
		}
	}
	if inTransition {
		color = "blue"
	} else if itemErr != nil {
		color = "red"
	} else if !created {
		color = "grey"
	} else {
		color = "black"
	}
	if !created {
		saturation = 0.12
	} else {
		saturation = 0.60
	}
	hue := e.hueMap[item.Type()]
	fillColor := fmt.Sprintf("%.3f %.3f 0.800", hue, saturation)
	label := item.Label()
	if label == "" {
		label = item.Name()
	}
	tooltip := item.String()
	if itemErr != nil {
		tooltip += fmt.Sprintf("\nError: %v", itemErr.Error())
	}
	_, err = w.WriteString(fmt.Sprintf("%s%s [color = %s, fillcolor = \"%s\", "+
		"shape = %s, style = filled, tooltip = \"%s\", label = \"%s\"];\n",
		indent, escapeName(Reference(item).String()), color, fillColor, shape,
		escapeTooltip(tooltip), label))
	return err
}

func (e *DotExporter) exportEdges(w io.StringWriter) (err error) {
	// Output all edges.
	// missingItems: not in the graph but with edges pointing to them
	missingItems := make(map[ItemRef]struct{})
	if e.graph != nil {
		itemIter := e.graph.Items(true)
		for itemIter.Next() {
			item, _ := itemIter.Item()
			edgeIter := e.graph.OutgoingEdges(Reference(item))
			for edgeIter.Next() {
				edge := edgeIter.Edge()
				err = e.exportEdge(w, edge, missingItems)
				if err != nil {
					return err
				}
			}
		}
	}
	if e.transition && e.dstGraph != nil {
		itemIter := e.dstGraph.Items(true)
		for itemIter.Next() {
			item, _ := itemIter.Item()
			if e.graph != nil {
				// Output only edges from items missing in src graph.
				if _, _, _, found := e.graph.Item(Reference(item)); found {
					continue
				}
			}
			edgeIter := e.dstGraph.OutgoingEdges(Reference(item))
			for edgeIter.Next() {
				edge := edgeIter.Edge()
				err = e.exportEdge(w, edge, missingItems)
				if err != nil {
					return err
				}
			}
		}
	}

	// Output missing items (not present in the graph but with edges pointing to them).
	for itemRef := range missingItems {
		_, err = w.WriteString(
			fmt.Sprintf("%s%s [color = grey, shape = ellipse, "+
				"style = dashed, tooltip = \"<missing>\", label = \"%s\"];\n",
				indentChar, escapeName(itemRef.String()), itemRef.String()))
		if err != nil {
			return  err
		}
	}
	return nil
}

func (e *DotExporter) exportEdge(w io.StringWriter, edge Edge,
	missingItems map[ItemRef]struct{}) (err error) {
	// Determine if edge points to a missing item.
	missingTarget := true
	if e.graph != nil {
		_, _, _, found := e.graph.Item(edge.ToItem)
		missingTarget = !found
		if missingTarget && e.transition && e.dstGraph != nil {
			_, _, _, found = e.dstGraph.Item(edge.ToItem)
			missingTarget = !found
		}
	}
	if missingTarget {
		missingItems[edge.ToItem] = struct{}{}
	}
	// Output the edge
	var color string
	if !e.CheckDeps || e.isDepSatisfied(edge) {
		color = "black"
	} else {
		color = "red"
	}
	_, err = w.WriteString(
		fmt.Sprintf("%s%s -> %s [color = %s, tooltip = \"%s\"];\n",
			indentChar, escapeName(edge.FromItem.String()),
			escapeName(edge.ToItem.String()), color,
			escapeTooltip(edge.Dependency.Description)))
	return err
}

// Generate Hue part of the HSV color for different types of items.
// Returns map: <item-type> -> <hue>
func (e *DotExporter) genHueMap() map[string]float32 {
	// Get and order item types to get deterministic outcome.
	itemTypesMap := make(map[string]struct{})
	if e.graph != nil {
		iter := e.graph.Items(true)
		for iter.Next() {
			item, _ := iter.Item()
			itemType := item.Type()
			itemTypesMap[itemType] = struct{}{}
		}
	}
	if e.transition && e.dstGraph != nil {
		iter := e.dstGraph.Items(true)
		for iter.Next() {
			item, _ := iter.Item()
			itemType := item.Type()
			itemTypesMap[itemType] = struct{}{}
		}
	}
	var itemTypes []string
	for itemType := range itemTypesMap {
		itemTypes = append(itemTypes, itemType)
	}
	sort.Strings(itemTypes)
	// Assign a distinct color to each item type.
	hueMap := make(map[string]float32)
	gradeCount := len(itemTypes)
	gradeInc := (float32(1) / 3) / float32(gradeCount+1)
	for i, itemType := range itemTypes {
		// chose color from between green and blue (avoid red)
		const green = float32(1) / 3
		hue := green + gradeInc*float32(i+1)
		hueMap[itemType] = hue
	}
	return hueMap
}

func (e *DotExporter) isDepSatisfied(edge Edge) bool {
	if e.graph == nil {
		return false
	}
	depItem, state, _, exists := e.graph.Item(edge.ToItem)
	if !exists {
		return false
	}
	if state != nil && !state.IsCreated() {
		return false
	}
	mustSatisfy := edge.Dependency.MustSatisfy
	if mustSatisfy != nil && !mustSatisfy(depItem) {
		return false
	}
	return true
}

func escapeName(name string) string {
	escapeChars := []string{"-", "/", ".", ":"}
	for _, char := range escapeChars {
		name = strings.Replace(name, char, "_", -1)
	}
	return name
}

func escapeTooltip(tooltip string) string {
	tooltip = strings.Replace(tooltip, "\n", "\\n", -1)
	tooltip = strings.Replace(tooltip, "\"", "\\\"", -1)
	return tooltip
}
