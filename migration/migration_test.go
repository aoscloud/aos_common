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

package migration_test

import (
	"database/sql"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	_ "github.com/mattn/go-sqlite3" // ignore lint
	log "github.com/sirupsen/logrus"

	"github.com/aosedge/aos_common/aoserrors"
	"github.com/aosedge/aos_common/migration"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	busyTimeout = 60000
	journalMode = "WAL"
	syncMode    = "NORMAL"
)

const folderPerm = 0o755

const testFolder = "/tmp/migration"

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

func TestSetCurrentVersion(t *testing.T) {
	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Fatalf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	checkDBVersion(t, 1, path.Join(testFolder, "test.db"))
	checkDBVersion(t, 25, path.Join(testFolder, "test.db"))
	checkDBVersion(t, 222229925, path.Join(testFolder, "test.db"))
	checkDBVersion(t, 0, path.Join(testFolder, "test.db"))
}

func TestDbMigrationUp(t *testing.T) {
	testMigration(t, uint(1), uint(25))
}

func TestDbMigrationDown(t *testing.T) {
	testMigration(t, uint(25), uint(1))
}

func TestDbMigrationSameVer(t *testing.T) {
	testMigration(t, uint(1), uint(1))
}

func TestMigrationFail(t *testing.T) {
	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	var (
		currentVersion uint = 1
		nextVersion    uint = 24
	)

	if err := createTestDB(path.Join(testFolder, "test.db"), currentVersion); err != nil {
		t.Errorf("Error preparing test db, err %s", err)
	}

	if err := generateMigrationFiles(currentVersion, path.Join(testFolder, "migrations1")); err != nil {
		t.Errorf("Can't generate migration files for ver %d", currentVersion)
	}

	if err := generateMigrationFiles(nextVersion, path.Join(testFolder, "migrations25")); err != nil {
		t.Errorf("Can't generate migration files for ver %d", nextVersion)
	}

	if err := breakMigrationVersion(13, path.Join(testFolder, "migrations25")); err != nil {
		t.Errorf("Can't break migration files for ver %d", nextVersion)
	}

	dbLocal, err := startMigrationRoutine(path.Join(testFolder, "test.db"), path.Join(testFolder, "migrations1"),
		path.Join(testFolder, "mergedMigration"), currentVersion)
	if err != nil {
		t.Fatalf("Can't create database: %s", err)
	}

	dbLocal.Close()

	if err = compareDBVersions(currentVersion, path.Join(testFolder, "test.db")); err != nil {
		t.Errorf("Compare error %s", err)
	}

	dbLocal, err = startMigrationRoutine(path.Join(testFolder, "test.db"), path.Join(testFolder, "migrations25"),
		path.Join(testFolder, "mergedMigration"), nextVersion)
	if err == nil {
		t.Fatalf("Database is expected to be failed")
	}

	dbLocal.Close()
}

func TestInitialMigration(t *testing.T) {
	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	var (
		initialVersion uint = 0
		nextVersion    uint = 25
	)

	if err := createTestDB(path.Join(testFolder, "test.db"), initialVersion); err != nil {
		t.Errorf("Error preparing test db, err %s", err)
	}

	if err := generateMigrationFiles(nextVersion, path.Join(testFolder, "migrations25")); err != nil {
		t.Errorf("Can't generate migration files for ver %d", nextVersion)
	}

	dbLocal, err := startMigrationRoutine(path.Join(testFolder, "test.db"), testFolder,
		path.Join(testFolder, "mergedMigration"), initialVersion)
	if err != nil {
		t.Errorf("Can't create database: %s", err)
	}

	// Removing schema_migrations from test db
	if err = removeMigrationDataFromDB(dbLocal); err != nil {
		t.Errorf("Unable to remove migration data")
	}

	dbLocal.Close()

	dbLocal, err = startMigrationRoutine(path.Join(testFolder, "test.db"), path.Join(testFolder, "migrations25"),
		path.Join(testFolder, "mergedMigration"), nextVersion)
	if err != nil {
		t.Errorf("Error during database creation: %s", err)
	}

	dbLocal.Close()

	if err = compareDBVersions(nextVersion, path.Join(testFolder, "test.db")); err != nil {
		t.Error("Db has wrong version")
	}
}

func TestSetDatabaseVersion(t *testing.T) {
	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	currentVersion := uint(12)
	name := path.Join(testFolder, "test.db")

	sqlite, err := getSQLConnection(name)
	if err != nil {
		t.Fatalf("Can't create database connection")
	}

	if err = migration.SetDatabaseVersion(sqlite, testFolder, currentVersion); err != nil {
		t.Fatalf("Can't set database version")
	}

	sqlite.Close()

	if err = compareDBVersions(currentVersion, name); err != nil {
		t.Errorf("Compare error : %s", err)
	}
}

func TestMergeMigrationFiles(t *testing.T) {
	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	srcDir := path.Join(testFolder, "srcDir")
	destDir := path.Join(testFolder, "destDir")

	files := []string{"file1", "file2", "file3"}

	if err := os.MkdirAll(srcDir, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	if err := os.MkdirAll(destDir, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	if err := createEmptyFile(filepath.Join(srcDir, files[0])); err != nil {
		t.Errorf("Can't create empty file %s", err)
	}

	if err := createEmptyFile(filepath.Join(srcDir, files[1])); err != nil {
		t.Errorf("Can't create empty file %s", err)
	}

	if err := createEmptyFile(filepath.Join(destDir, files[1])); err != nil {
		t.Errorf("Can't create empty file %s", err)
	}

	if err := createEmptyFile(filepath.Join(destDir, files[2])); err != nil {
		t.Fatalf("Can't create empty file %s", err)
	}

	if err := migration.MergeMigrationFiles(srcDir, destDir); err != nil {
		t.Fatalf("Can't merge migration files %s", err)
	}

	destFiles, err := os.ReadDir(destDir)
	if err != nil {
		t.Fatalf("Can't read destination directory")
	}

	for _, f := range destFiles {
		if sort.SearchStrings(files, f.Name()) == len(files) {
			t.Fatalf("Error, can't find file %s in merged path", f)
		}
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func createEmptyFile(path string) (err error) {
	srcFile, err := os.Create(path)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer srcFile.Close()

	return nil
}

func compareDBVersions(currentVersion uint, name string) (err error) {
	// Check database version
	dbVersion, dirty, err := getCurrentDBVersion(name)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if dirty == true || dbVersion != currentVersion {
		return aoserrors.New("DB versions are different")
	}

	return nil
}

func createTestDB(dbName string, version uint) (err error) {
	conn := fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_sync=%s",
		dbName, busyTimeout, journalMode, syncMode)

	sql, err := sql.Open("sqlite3", conn)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer sql.Close()

	// DB preparation
	if _, err = sql.Exec(
		`CREATE TABLE testing (
			version INTEGER)`); err != nil {
		return aoserrors.Wrap(err)
	}

	if _, err = sql.Exec(
		`INSERT INTO testing (
			version) values (?)`, version); err != nil {
		return aoserrors.Wrap(err)
	}

	if _, err := getOperationVersion(sql); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func breakMigrationVersion(ver uint, path string) (err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	upScript := fmt.Sprintf("UPDATE broken_base SET version = %d;", ver)
	upPath := filepath.Join(abs, fmt.Sprintf("%d_update.up.sql", ver))

	if err = writeToFile(upPath, upScript); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func generateMigrationFiles(verTo uint, path string) (err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.MkdirAll(abs, folderPerm); err != nil {
		return aoserrors.Wrap(err)
	}

	var i uint

	for i = 0; i <= verTo; i++ {
		upScript := fmt.Sprintf("UPDATE testing SET version = %d;", i)
		upPath := filepath.Join(abs, fmt.Sprintf("%d_update.up.sql", i))
		downPath := filepath.Join(abs, fmt.Sprintf("%d_update.down.sql", i-1))
		downScript := fmt.Sprintf("UPDATE testing SET version = %d;", i-1)

		if err = writeToFile(upPath, upScript); err != nil {
			return err
		}

		if err = writeToFile(downPath, downScript); err != nil {
			return err
		}
	}

	return nil
}

func removeMigrationDataFromDB(sqlite *sql.DB) (err error) {
	_, err = sqlite.Exec("DROP TABLE IF EXISTS schema_migrations")

	return aoserrors.Wrap(err)
}

func getCurrentDBVersion(name string) (version uint, dirty bool, err error) {
	sql, err := sql.Open("sqlite3", fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_sync=%s",
		name, busyTimeout, journalMode, syncMode))
	if err != nil {
		return 0, false, aoserrors.Wrap(err)
	}
	defer sql.Close()

	stmt, err := sql.Prepare("SELECT version, dirty FROM schema_migrations LIMIT 1")
	if err != nil {
		return 0, false, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&version, &dirty)
	if err != nil {
		return 0, false, aoserrors.Wrap(err)
	}

	log.Debugf("version: %d, dirty: %v", version, dirty)

	return version, dirty, nil
}

func getOperationVersion(sql *sql.DB) (version int, err error) {
	stmt, err := sql.Prepare("SELECT version FROM testing")
	if err != nil {
		return version, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&version)
	if err != nil {
		return version, aoserrors.Wrap(err)
	}

	return version, nil
}

func writeToFile(path string, data string) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	defer file.Close()

	if _, err := file.WriteString(data); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func checkDBVersion(t *testing.T, currentVersion uint, name string) {
	t.Helper()

	if err := os.RemoveAll(name); err != nil {
		t.Fatalf("Error cleaning up: %s", err)
	}

	dbLocal, err := startMigrationRoutine(name, testFolder, testFolder, currentVersion)
	if err != nil {
		t.Errorf("Can't create database: %s", err)
	}

	dbLocal.Close()

	if err = compareDBVersions(currentVersion, name); err != nil {
		t.Errorf("Compare error : %s", err)
	}
}

func testMigration(t *testing.T, currentVersion uint, nextVersion uint) {
	t.Helper()

	if err := os.MkdirAll(testFolder, folderPerm); err != nil {
		t.Errorf("Error creating directory: %s", err)
	}

	defer func() {
		if err := os.RemoveAll(testFolder); err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	}()

	if err := createTestDB(path.Join(testFolder, "test.db"), currentVersion); err != nil {
		t.Errorf("Error preparing test db, err %s", err)
	}

	if err := generateMigrationFiles(currentVersion, path.Join(testFolder, "migrations1")); err != nil {
		t.Errorf("Can't generate migration files for ver %d", currentVersion)
	}

	if err := generateMigrationFiles(nextVersion, path.Join(testFolder, "migrations25")); err != nil {
		t.Errorf("Can't generate migration files for ver %d", nextVersion)
	}

	dbLocal, err := startMigrationRoutine(path.Join(testFolder, "test.db"), path.Join(testFolder, "migrations1"),
		path.Join(testFolder, "mergedMigration"), currentVersion)
	if err != nil {
		t.Errorf("Can't create database: %s", err)
	}

	dbLocal.Close()

	if err = compareDBVersions(currentVersion, path.Join(testFolder, "test.db")); err != nil {
		t.Errorf("Compare error %s", err)
	}

	dbLocal, err = startMigrationRoutine(path.Join(testFolder, "test.db"), path.Join(testFolder, "migrations25"),
		path.Join(testFolder, "mergedMigration"), nextVersion)
	if err != nil {
		t.Errorf("Can't create database: %s", err)
	}

	dbLocal.Close()

	if err = compareDBVersions(nextVersion, path.Join(testFolder, "test.db")); err != nil {
		t.Errorf("Compare error %s", err)
	}
}

func startMigrationRoutine(
	name string, migrationPath string, mergedMigrationPath string, version uint,
) (sqlite *sql.DB, err error) {
	// Check and create db
	if _, err = os.Stat(filepath.Dir(name)); err != nil {
		if !os.IsNotExist(err) {
			return nil, aoserrors.Wrap(err)
		}

		if err = os.MkdirAll(filepath.Dir(name), folderPerm); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	exists := true
	if _, err := os.Stat(name); os.IsNotExist(err) {
		exists = false
	}

	sqlite, err = getSQLConnection(name)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			sqlite.Close()
		}
	}()

	if err = migration.MergeMigrationFiles(migrationPath, mergedMigrationPath); err != nil {
		return sqlite, aoserrors.Wrap(err)
	}

	if !exists {
		// Set database version if database not exist
		if err = migration.SetDatabaseVersion(sqlite, migrationPath, version); err != nil {
			return sqlite, aoserrors.Wrap(err)
		}
	} else {
		if err = migration.DoMigrate(sqlite, mergedMigrationPath, version); err != nil {
			return sqlite, aoserrors.Wrap(err)
		}
	}

	return sqlite, nil
}

func getSQLConnection(name string) (sqlite *sql.DB, err error) {
	if sqlite, err = sql.Open("sqlite3", fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_sync=%s",
		name, busyTimeout, journalMode, syncMode)); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return sqlite, nil
}
