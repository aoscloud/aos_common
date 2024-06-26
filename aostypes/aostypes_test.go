// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2022 Renesas Electronics Corporation.
// Copyright (C) 2022 EPAM Systems, Inc.
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

package aostypes_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aosedge/aos_common/aostypes"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	dayDuration   = 24 * time.Hour
	weekDuration  = 7 * dayDuration
	yearDuration  = 365*dayDuration + 6*time.Hour
	monthDuration = yearDuration / 12
)

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestTimeMarshalign(t *testing.T) {
	type testData struct {
		rawJSON string
		time    aostypes.Time
	}

	unmarshalData := []testData{
		{rawJSON: `{"time":"T01"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 0, 0, 0, time.Local)}},
		{rawJSON: `{"time":"T04"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 0, 0, 0, time.Local)}},
		{rawJSON: `{"time":"T0102"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 2, 0, 0, time.Local)}},
		{rawJSON: `{"time":"T0405"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 5, 0, 0, time.Local)}},
		{rawJSON: `{"time":"T010203"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 2, 3, 0, time.Local)}},
		{rawJSON: `{"time":"T040506"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 5, 6, 0, time.Local)}},
		{rawJSON: `{"time":"01:02"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 2, 0, 0, time.Local)}},
		{rawJSON: `{"time":"04:05"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 5, 0, 0, time.Local)}},
		{rawJSON: `{"time":"01:02:03"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 2, 3, 0, time.Local)}},
		{rawJSON: `{"time":"04:05:06"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 5, 6, 0, time.Local)}},
	}

	for _, item := range unmarshalData {
		var testTime struct {
			Time aostypes.Time `json:"time"`
		}

		if err := json.Unmarshal([]byte(item.rawJSON), &testTime); err != nil {
			t.Errorf("Can't unmarshal json: %s", err)

			continue
		}

		if !item.time.Equal(testTime.Time.Time) {
			t.Errorf("Wrong time value: %v", testTime)
		}
	}

	marshalData := []testData{
		{rawJSON: `{"time":"01:02:03"}`, time: aostypes.Time{time.Date(0, 1, 1, 1, 2, 3, 0, time.Local)}},
		{rawJSON: `{"time":"04:05:06"}`, time: aostypes.Time{time.Date(0, 1, 1, 4, 5, 6, 0, time.Local)}},
		{rawJSON: `{"time":"07:08:09"}`, time: aostypes.Time{time.Date(0, 1, 1, 7, 8, 9, 0, time.Local)}},
		{rawJSON: `{"time":"10:11:12"}`, time: aostypes.Time{time.Date(0, 1, 1, 10, 11, 12, 0, time.Local)}},
	}

	for _, item := range marshalData {
		testTime := struct {
			Time aostypes.Time `json:"time"`
		}{Time: item.time}

		rawJSON, err := json.Marshal(&testTime)
		if err != nil {
			t.Errorf("Can't marshal json: %s", err)

			continue
		}

		if string(rawJSON) != item.rawJSON {
			t.Errorf("Wrong json data: %s", string(rawJSON))
		}
	}
}

func TestDurationMarshal(t *testing.T) {
	type testData struct {
		rawJSON  string
		duration aostypes.Duration
	}

	unmarshalData := []testData{
		{rawJSON: `{"duration":"10s"}`, duration: aostypes.Duration{10 * time.Second}},
		{rawJSON: `{"duration":"1m30s"}`, duration: aostypes.Duration{90 * time.Second}},
		{rawJSON: `{"duration":"PT10S"}`, duration: aostypes.Duration{10 * time.Second}},
		{rawJSON: `{"duration":"PT1M30S"}`, duration: aostypes.Duration{90 * time.Second}},
		{rawJSON: `{"duration":"P10Y"}`, duration: aostypes.Duration{10 * yearDuration}},
		{rawJSON: `{"duration":"P10M"}`, duration: aostypes.Duration{10 * monthDuration}},
		{rawJSON: `{"duration":"P2W"}`, duration: aostypes.Duration{2 * weekDuration}},
		{rawJSON: `{"duration":"P2D"}`, duration: aostypes.Duration{2 * dayDuration}},
		{rawJSON: `{"duration":"P1Y1M1W1DT1H1M1S"}`, duration: aostypes.Duration{
			yearDuration + monthDuration + weekDuration + dayDuration + time.Hour + time.Minute + time.Second,
		}},
		{rawJSON: `{"duration":"PT00:00:10"}`, duration: aostypes.Duration{10 * time.Second}},
		{rawJSON: `{"duration":"PT00:01:30"}`, duration: aostypes.Duration{90 * time.Second}},
		{rawJSON: `{"duration":"P0001-01-01T01:01:01"}`, duration: aostypes.Duration{
			yearDuration + monthDuration + dayDuration + time.Hour + time.Minute + time.Second,
		}},
	}

	for _, item := range unmarshalData {
		var testDuration struct {
			Duration aostypes.Duration `json:"duration"`
		}

		if err := json.Unmarshal([]byte(item.rawJSON), &testDuration); err != nil {
			t.Errorf("Can't unmarshal json: %s", err)

			continue
		}

		if testDuration.Duration != item.duration {
			t.Errorf("Wrong time value: %v", testDuration)
		}
	}

	// test invalid formats
	invalidUnmarshalData := []string{
		`{"duration":"T1H1M1S"}`,
		`{"duration":"P0001-01T01:01:01"}`,
		`{"duration":"P0001-01-01T01:01"}`,
	}

	for _, item := range invalidUnmarshalData {
		var testDuration struct {
			Duration aostypes.Duration `json:"duration"`
		}

		if err := json.Unmarshal([]byte(item), &testDuration); err == nil {
			t.Errorf("Should be error unmarshal for duration: %s", item)
		}
	}

	marshalData := []testData{
		{rawJSON: `{"duration":"30m0s"}`, duration: aostypes.Duration{30 * time.Minute}},
		{rawJSON: `{"duration":"24h0m0s"}`, duration: aostypes.Duration{24 * time.Hour}},
	}

	for _, item := range marshalData {
		testDuration := struct {
			Duration aostypes.Duration `json:"duration"`
		}{Duration: item.duration}

		rawJSON, err := json.Marshal(&testDuration)
		if err != nil {
			t.Errorf("Can't marshal json: %s", err)

			continue
		}

		if string(rawJSON) != item.rawJSON {
			t.Errorf("Wrong json data: %s", string(rawJSON))
		}
	}
}
