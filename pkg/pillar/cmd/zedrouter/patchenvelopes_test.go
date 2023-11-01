// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter_test

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedrouter"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func TestPatchEnvelopes(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "petypes", 1234)
	peStore := zedrouter.NewPatchEnvelopes(log)

	u := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	contentU := "6ba7b810-9dad-11d1-80b4-ffffffffffff"
	u1, err := uuid.FromString(u)
	g.Expect(err).To(gomega.BeNil())
	u2, err := uuid.FromString(contentU)
	g.Expect(err).To(gomega.BeNil())
	fileSHA := "someFileSha"
	f := "some/File/Location.txt"

	volumeStatuses := []types.VolumeStatus{
		{
			VolumeID:     u1,
			ContentID:    u2,
			State:        types.INSTALLED,
			FileLocation: f,
		},
	}

	contentStatuses := []types.ContentTreeStatus{
		{
			ContentID:     u2,
			ContentSha256: fileSHA,
		},
	}

	peInfo := []types.PatchEnvelopeInfo{
		{
			PatchID:     "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			AllowedApps: []string{u},
			BinaryBlobs: []types.BinaryBlobCompleted{
				{
					FileName:     "TestFileName",
					FileSha:      "TestFileSha",
					FileMetadata: "TestFileMetadata",
					URL:          "./testurl",
				},
			},
			VolumeRefs: []types.BinaryBlobVolumeRef{
				{
					FileName:     "VolTestFileName",
					ImageName:    "VolTestImageName",
					FileMetadata: "VolTestFileMetadata",
					ImageID:      u,
				},
			},
		},
	}

	go func() {
		for _, vs := range volumeStatuses {
			peStore.UpdateVolumeStatus(vs, false)
			peStore.UpdateStateNotificationCh() <- struct{}{}
		}
	}()

	go func() {
		for _, ct := range contentStatuses {
			peStore.UpdateContentTree(ct, false)

			peStore.UpdateStateNotificationCh() <- struct{}{}
		}
	}()

	go func() {
		peStore.UpdateEnvelopes(peInfo)

		peStore.UpdateStateNotificationCh() <- struct{}{}

	}()

	finishedProcessing := make(chan struct{})
	go func() {
		for {
			if len(peStore.Get(u).Envelopes) > 0 && len(peStore.Get(u).Envelopes[0].BinaryBlobs) >= 2 {
				close(finishedProcessing)
				return
			}
			time.Sleep(time.Second)
		}
	}()

	g.Eventually(func() bool {
		select {
		case <-finishedProcessing:
			return true
		case <-time.After(time.Minute):
			return false
		}
	}, 2*time.Minute, time.Second).Should(gomega.BeTrue())

	g.Expect(peStore.Get(u).Envelopes).To(gomega.BeEquivalentTo(
		[]types.PatchEnvelopeInfo{
			{
				PatchID:     "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				AllowedApps: []string{u},
				BinaryBlobs: []types.BinaryBlobCompleted{
					{
						FileName:     "TestFileName",
						FileSha:      "TestFileSha",
						FileMetadata: "TestFileMetadata",
						URL:          "./testurl",
					},
					{
						FileName: "VolTestFileName",
						//pragma: allowlist nextline secret
						FileSha:      fileSHA,
						FileMetadata: "VolTestFileMetadata",
						URL:          f,
					},
				},
				VolumeRefs: []types.BinaryBlobVolumeRef{
					{
						FileName:     "VolTestFileName",
						ImageName:    "VolTestImageName",
						FileMetadata: "VolTestFileMetadata",
						ImageID:      u,
					},
				},
			},
		}))
}
