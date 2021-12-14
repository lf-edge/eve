// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A simple demonstration of reconciler + depgraph.
// Files, directories and their dependencies are represented using dependency
// graphs. Reconciler then takes care of the reconciliation between the intended
// and the actual content of a (temporary) directory.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
)

type demo struct {
	registry      *reconciler.DefaultRegistry
	currentState  depgraph.Graph
	intendedState depgraph.Graph
}

func (d *demo) init() {
	// Build configurator registry.
	d.registry = &reconciler.DefaultRegistry{}
	err := d.registry.Register(fileConfigurator{}, file{}.Type())
	if err != nil {
		log.Fatalf("Failed to register configurator for files: %v", err)
	}
	err = d.registry.Register(dirConfigurator{}, directory{}.Type())
	if err != nil {
		log.Fatalf("Failed to register configurator for directories: %v", err)
	}
	// Allow to visualize current/intended state using online Graphviz.
	d.redirectGraphvizRendering()
}

func (d *demo) run() {
	const graphName = "Reconciler Demo"

	// Create root directory for our file-sync demo.
	rootDirname, err := ioutil.TempDir("/tmp", "file-sync-demo-")
	if err != nil {
		log.Fatalf("Failed to create root directory for the demo: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(rootDirname)
	}()

	// Root directory was created externally (outside of the Reconciler).
	rootDir := directory{dirname: rootDirname, permissions: 0755}
	d.currentState = depgraph.New(depgraph.InitArgs{
		Name: graphName,
		ItemsWithState: []depgraph.ItemWithState{
			{
				Item: rootDir,
				State: &reconciler.ItemStateData{
					State:         reconciler.ItemStateCreated,
					LastOperation: reconciler.OperationCreate,
					LastError:     nil,
				},
			},
		},
	})

	// 1. Initial intended state of the directory content.
	//    We want directory with svg images, further sorted between sub-directories.
	//    The whole svg-image directory and all its content will be grouped by a *subgraph*.
	//    Then we want directory with shell scripts and another empty directory later used
	//    for text files.
	description := fmt.Sprintf(`%s
├── svg-images (this directory and all its content is grouped by a subgraph)
│   ├── circles
│   │   ├── one-circle.svg
│   │   └── two-circles.svg
│   └── squares
│       └── one-square.svg
├── scripts
│   ├── hello-world.sh
│   └── ls.sh
└── text-files (empty dir)
`, rootDirname)
	svgImagesDir := directory{dirname: "svg-images", parent: &rootDir, permissions: 0755}
	circlesDir := directory{dirname: "circles", parent: &svgImagesDir, permissions: 0755}
	squaresDir := directory{dirname: "squares", parent: &svgImagesDir, permissions: 0755}
	scriptsDir := directory{dirname: "scripts", parent: &rootDir, permissions: 0755}
	textFilesDir := directory{dirname: "text-files", parent: &rootDir, permissions: 0755}

	oneCircleFile := file{id: newFileID(), filename: "one-circle.svg",
		content: d.svgImageCircles(1), permissions: 0644, parentDir: &circlesDir}
	twoCircleFile := file{id: newFileID(), filename: "two-circles.svg",
		content: d.svgImageCircles(2), permissions: 0644, parentDir: &circlesDir}
	oneSquareFile := file{id: newFileID(), filename: "one-square.svg",
		content: d.svgImageSquares(1), permissions: 0644, parentDir: &squaresDir}
	helloWorldFile := file{id: newFileID(), filename: "hello-world.sh",
		content: d.shellScript("echo 'Hello world!'"), permissions: 0744, parentDir: &scriptsDir}
	lsFile := file{id: newFileID(), filename: "ls.sh",
		content: d.shellScript("ls -al"), permissions: 0744, parentDir: &scriptsDir}

	d.intendedState = depgraph.New(depgraph.InitArgs{
		Name: graphName,
		Items: []depgraph.Item{
			rootDir,
			scriptsDir,
			textFilesDir,
			helloWorldFile,
			lsFile,
		},
		Subgraphs: []depgraph.InitArgs{
			{
				Name:        "svg-images",
				Description: "All SVG images",
				Items: []depgraph.Item{
					svgImagesDir,
					circlesDir,
					squaresDir,
					oneCircleFile,
					twoCircleFile,
					oneSquareFile,
				},
			},
		},
	})

	r := reconciler.New(d.registry)
	status := r.Reconcile(context.Background(), d.currentState, d.intendedState)
	if status.Err != nil {
		log.Fatalf("State reconciliation failed: %v", status.Err)
	}

	// Inform the user.
	d.printReport("Applied the intended state:")
	fmt.Println(description)
	d.printReport("Visualization of the graph with the current state: %s ",
		gvRedirectURL+gvCurrentState)
	d.printReport("Visualization of the graph with the intended state: %s ",
		gvRedirectURL+gvIntendedState)
	d.printReport("Visualization of the merged current and the intended state: %s ",
		gvRedirectURL+gvMergedState)
	d.printReport("Verify the content of %s and press ENTER to continue", rootDirname)
	_, _ = fmt.Scanln()

	// 2. Next intended state of the directory content.
	//    Now we want all svg images to be directly under svg-images.
	//    Script ls.sh should no longer exist. Script hello-world.sh has modified content.
	//    Directory with text files should now contain two files.
	//    Reconciler will perform create/modify/delete operations to get from the current
	//    state to the new intended state.
	description = fmt.Sprintf(`%s
├── svg-images
│   ├── one-circle.svg (moved)
│   ├── two-circles.svg (moved)
│   └── one-square.svg (moved)
├── scripts
│   └── hello-world.sh (modified to German language)
└── text-files
    ├── empty-file.txt (new)
    └── sample-file.txt (new)
`, rootDirname)
	oneCircleFile.parentDir = &svgImagesDir
	twoCircleFile.parentDir = &svgImagesDir
	oneSquareFile.parentDir = &svgImagesDir

	helloWorldFile.content = d.shellScript("echo 'Hallo Welt!'")
	emptyFile := file{id: newFileID(), filename: "empty-file.txt",
		content: "", permissions: 0644, parentDir: &textFilesDir}
	sampleFile := file{id: newFileID(), filename: "sample-file.txt",
		content: "sample", permissions: 0644, parentDir: &textFilesDir}

	d.intendedState = depgraph.New(depgraph.InitArgs{
		Name: graphName,
		Items: []depgraph.Item{
			rootDir,
			scriptsDir,
			textFilesDir,
			helloWorldFile,
			emptyFile,
			sampleFile,
		},
		Subgraphs: []depgraph.InitArgs{
			{
				Name:        "svg-images",
				Description: "All SVG images",
				Items: []depgraph.Item{
					svgImagesDir,
					oneCircleFile,
					twoCircleFile,
					oneSquareFile,
				},
			},
		},
	})

	r = reconciler.New(d.registry)
	status = r.Reconcile(context.Background(), d.currentState, d.intendedState)
	if status.Err != nil {
		log.Fatalf("State reconciliation failed: %v", status.Err)
	}

	// Inform the user.
	d.printReport("Applied the intended state:")
	fmt.Println(description)
	d.printReport("Visualization of the graph with the current state: %s ",
		gvRedirectURL+gvCurrentState)
	d.printReport("Visualization of the graph with the intended state: %s ",
		gvRedirectURL+gvIntendedState)
	d.printReport("Visualization of the merged current and the intended state: %s ",
		gvRedirectURL+gvMergedState)
	d.printReport("Verify the content of %s and press ENTER to continue", rootDirname)
	_, _ = fmt.Scanln()

	// 3. Finally, remove the root from the graph of the current state (even before it is
	//    actually removed). Since everything either directly or transitively depends on it,
	//    all files and directories will be removed by Reconciler.
	d.currentState.DelItem(depgraph.Reference(rootDir))
	r = reconciler.New(d.registry)
	status = r.Reconcile(context.Background(), d.currentState, d.intendedState)
	if status.Err != nil {
		log.Fatalf("State reconciliation failed: %v", status.Err)
	}

	// Inform the user.
	d.printReport("Removed root from the current-state graph.")
	d.printReport("All files and directories under %s should be removed "+
		"by the Reconciler.", rootDirname)
	d.printReport("Visualization of the graph with the current state: %s ",
		gvRedirectURL+gvCurrentState)
	d.printReport("Visualization of the graph with the intended state: %s ",
		gvRedirectURL+gvIntendedState)
	d.printReport("Visualization of the merged current and the intended state: %s ",
		gvRedirectURL+gvMergedState)
	d.printReport("Verify the content of %s and press ENTER to continue", rootDirname)
	_, _ = fmt.Scanln()
}

func main() {
	d := &demo{}
	d.init()
	d.run()
}
