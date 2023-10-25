// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package persistcache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/persistcache"
	"github.com/onsi/gomega"
)

type persistObj struct {
	Name string
	Val  []byte
}

func TestPut(test *testing.T) {
	test.Parallel()

	g := gomega.NewGomegaWithT(test)

	path, err := os.MkdirTemp("", "testFolder")
	g.Expect(err).To(gomega.BeNil())

	persistCacheFolder := filepath.Join(path, "testPersist/")
	defer os.RemoveAll(persistCacheFolder)

	pc, err := persistcache.New(persistCacheFolder)
	g.Expect(err).To(gomega.BeNil())

	// Create
	obj1 := persistObj{
		Name: "object1",
		Val:  []byte("123"),
	}
	_, err = pc.Put(obj1.Name, obj1.Val)
	g.Expect(err).To(gomega.BeNil())

	got, err := pc.Get(obj1.Name)
	g.Expect(err).To(gomega.BeNil())

	g.Expect(got).To(gomega.BeEquivalentTo(obj1.Val))

	// Update
	newVal := []byte("320")
	_, err = pc.Put(obj1.Name, newVal)
	g.Expect(err).To(gomega.BeNil())

	got, _ = pc.Get(obj1.Name)
	g.Expect(got).To(gomega.BeEquivalentTo(newVal))

	// Try to insert malicious key
	gotFp, err := pc.Put("../../../../etc/passwd", []byte("myNewPassword"))
	g.Expect(err).To(gomega.BeEquivalentTo(&persistcache.InvalidKeyError{}))
	g.Expect(gotFp).To(gomega.BeEquivalentTo(""))

	// Try to insert empty value
	gotFp, err = pc.Put("dummy", []byte{})
	g.Expect(err).To(gomega.BeEquivalentTo(&persistcache.InvalidKeyError{}))
	g.Expect(gotFp).To(gomega.BeEquivalentTo(""))
}

func TestDelete(test *testing.T) {
	test.Parallel()

	g := gomega.NewGomegaWithT(test)

	path, err := os.MkdirTemp("", "testFolder")
	g.Expect(err).To(gomega.BeNil())

	persistCacheFolder := filepath.Join(path, "testPersist/")
	defer os.RemoveAll(persistCacheFolder)

	obj1 := persistObj{
		Name: "object1",
		Val:  []byte("123"),
	}
	obj2 := persistObj{
		Name: "object2",
		Val:  []byte("ordinaryVal"),
	}

	pc, _ := persistcache.New(persistCacheFolder)
	_, err = pc.Put(obj1.Name, obj1.Val)
	g.Expect(err).To(gomega.BeNil())

	_, err = pc.Put(obj2.Name, obj2.Val)
	g.Expect(err).To(gomega.BeNil())

	val, err := pc.Get(obj1.Name)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(obj1.Val))

	err = pc.Delete(obj1.Name)
	g.Expect(err).To(gomega.BeNil())

	val, err = pc.Get(obj1.Name)
	g.Expect(err).NotTo(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(""))
}

func TestLoad(test *testing.T) {
	test.Parallel()

	g := gomega.NewGomegaWithT(test)

	path, err := os.MkdirTemp("", "testFolder")
	g.Expect(err).To(gomega.BeNil())

	persistCacheFolder := filepath.Join(path, "testPersist/")
	defer os.RemoveAll(persistCacheFolder)

	obj1 := persistObj{
		Name: "object1",
		Val:  []byte("123"),
	}
	obj2 := persistObj{
		Name: "object2",
		Val:  []byte("bazinga"),
	}

	pc, err := persistcache.New(persistCacheFolder)
	g.Expect(err).To(gomega.BeNil())

	_, err = pc.Put(obj1.Name, obj1.Val)
	g.Expect(err).To(gomega.BeNil())

	_, err = pc.Put(obj2.Name, obj2.Val)
	g.Expect(err).To(gomega.BeNil())

	val, err := pc.Get(obj1.Name)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(obj1.Val))

	val, err = pc.Get(obj2.Name)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(obj2.Val))

	pc2, err := persistcache.New(persistCacheFolder)
	g.Expect(err).To(gomega.BeNil())

	val, err = pc2.Get(obj1.Name)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(obj1.Val))

	val, err = pc2.Get(obj2.Name)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(val).To(gomega.BeEquivalentTo(obj2.Val))
}
