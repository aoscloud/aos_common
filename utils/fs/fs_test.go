// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fs_test

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/fs"
	"github.com/aoscloud/aos_common/utils/testtools"
)

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	disk       *testtools.TestDisk
	mountPoint string
	tmpDir     string
)

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func TestMain(m *testing.M) {
	var err error

	if tmpDir, err = ioutil.TempDir("", "um_"); err != nil {
		log.Fatalf("Error creating tmp dir: %s", err)
	}

	mountPoint = path.Join(tmpDir, "mount")

	if disk, err = testtools.NewTestDisk(
		path.Join(tmpDir, "testdisk.img"),
		[]testtools.PartDesc{
			{Type: "vfat", Label: "efi", Size: 16},
			{Type: "ext4", Label: "platform", Size: 32},
		}); err != nil {
		log.Fatalf("Can't create test disk: %s", err)
	}

	ret := m.Run()

	if err = disk.Close(); err != nil {
		log.Fatalf("Can't close test disk: %s", err)
	}

	if err = os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing tmp dir: %s", err)
	}

	os.Exit(ret)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestMountUmountContinued(t *testing.T) {
	for i := 0; i < 50; i++ {
		mountUmount(t)
	}
}

func TestMountAlreadyMounted(t *testing.T) {
	for _, part := range disk.Partitions {
		if err := fs.Mount(part.Device, mountPoint, part.Type, 0, ""); err != nil {
			t.Fatalf("Can't mount partition: %s", err)
		}

		if err := fs.Mount(part.Device, mountPoint, part.Type, 0, ""); err != nil {
			t.Fatalf("Can't mount partition: %s", err)
		}

		if err := fs.Umount(mountPoint); err != nil {
			t.Fatalf("Can't umount partition: %s", err)
		}
	}
}

func TestOverlayMount(t *testing.T) {
	content := []string{"file0", "file1", "file2", "file3", "file4", "file5", "file6"}
	lowerDirs := []string{
		filepath.Join(tmpDir, "lower0"), filepath.Join(tmpDir, "lower1"),
		filepath.Join(tmpDir, "lower2"),
	}

	// Create content

	if err := createDirContent(lowerDirs[0], content[:2]); err != nil {
		t.Fatalf("Can't create lower dir content: %s", err)
	}

	if err := createDirContent(lowerDirs[1], content[2:4]); err != nil {
		t.Fatalf("Can't create lower dir content: %s", err)
	}

	if err := createDirContent(lowerDirs[2], content[4:]); err != nil {
		t.Fatalf("Can't create lower dir content: %s", err)
	}

	workDir := filepath.Join(tmpDir, "workDir")

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("Can't create work dir: %s", err)
	}

	upperDir := filepath.Join(tmpDir, "upperDir")

	if err := os.MkdirAll(upperDir, 0o755); err != nil {
		t.Fatalf("Can't create upper dir: %s", err)
	}

	// Overlay mount

	if err := fs.OverlayMount(mountPoint, lowerDirs, workDir, upperDir); err != nil {
		t.Fatalf("Can't mount overlay dir: %s", err)
	}

	// Check content

	if err := checkContent(mountPoint, content); err != nil {
		t.Errorf("Overlay content mismatch: %s", err)
	}

	// Write some file

	newContent := []string{"newFile0", "newFile1", "newFile2"}

	if err := createDirContent(mountPoint, newContent); err != nil {
		t.Fatalf("Can't create new content: %s", err)
	}

	if err := fs.Umount(mountPoint); err != nil {
		t.Errorf("Can't unmount overlay dir: %s", err)
	}

	// New content should be in upper dir

	if err := checkContent(upperDir, newContent); err != nil {
		t.Errorf("Upper dir content mismatch: %s", err)
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func mountUmount(t *testing.T) {
	t.Helper()

	for _, part := range disk.Partitions {
		if err := fs.Mount(part.Device, mountPoint, part.Type, 0, ""); err != nil {
			t.Fatalf("Can't mount partition: %s", err)
		}

		if err := fs.Umount(mountPoint); err != nil {
			t.Fatalf("Can't umount partition: %s", err)
		}
	}
}

func createDirContent(path string, content []string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return aoserrors.Wrap(err)
	}

	for _, fileName := range content {
		file, err := os.Create(filepath.Join(path, fileName))
		if err != nil {
			return aoserrors.Wrap(err)
		}

		file.Close()
	}

	return nil
}

func checkContent(path string, content []string) error {
	file, err := os.Open(path)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	dirContent, err := file.Readdir(0)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if len(dirContent) != len(content) {
		return aoserrors.Errorf("wrong files count: %d", len(dirContent))
	}

contentLoop:
	for _, fileName := range content {
		for _, item := range dirContent {
			if fileName == item.Name() {
				continue contentLoop
			}
		}

		return aoserrors.Errorf("file %s not found", fileName)
	}

	return nil
}
