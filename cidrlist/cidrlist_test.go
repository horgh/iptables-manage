package cidrlist

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestRecordIP(t *testing.T) {
	tests := []struct {
		IP            string
		Comment       string
		PriorContents string
		Records       []Record
		WantError     error
	}{
		// Invalid IP.
		{
			IP:            "junk",
			Comment:       "",
			PriorContents: "",
			Records:       []Record{},
			WantError:     fmt.Errorf("invalid IP: junk"),
		},

		// File doesn't exist.
		{
			IP:            "192.168.1.3",
			Comment:       "test 1 2 3",
			PriorContents: "",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.3"),
						Mask: net.CIDRMask(32, 32),
					},
					Comment: "test 1 2 3",
				},
			},
			WantError: nil,
		},

		// Invalid record present.
		{
			IP:            "192.168.1.3",
			Comment:       "test 1 2 3",
			PriorContents: "junk\n",
			Records:       []Record{},
			WantError: fmt.Errorf(
				"unable to load records: invalid CIDR address: junk"),
		},

		// IP is listed twice.
		{
			IP:            "192.168.1.3",
			Comment:       "test 1 2 3",
			PriorContents: "192.168.1.3/32\n192.168.1.0/24\n",
			Records:       []Record{},
			WantError:     fmt.Errorf("ip is listed twice: 192.168.1.3: 192.168.1.3/32 and 192.168.1.0/24"),
		},

		// IP is not in file yet.
		{
			IP:            "192.168.1.4",
			Comment:       "test 1 2 3",
			PriorContents: "192.168.1.3/32\n",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.3"),
						Mask: net.CIDRMask(32, 32),
					},
					Comment: "",
				},
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.4"),
						Mask: net.CIDRMask(32, 32),
					},
					Comment: "test 1 2 3",
				},
			},
			WantError: nil,
		},

		// IP is in as a different CIDR already.
		{
			IP:            "192.168.1.4",
			Comment:       "test 1 2 3",
			PriorContents: "# nice comment\n192.168.1.0/24\n# another nice comment\n192.168.2.0/24",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.2.0"),
						Mask: net.CIDRMask(24, 32),
					},
					Comment: "another nice comment",
				},
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
					Comment: "test 1 2 3",
				},
			},
			WantError: nil,
		},
		{
			IP:            "::1",
			Comment:       "test 1 2 3",
			PriorContents: "",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("::1"),
						Mask: net.CIDRMask(128, 128),
					},
					Comment: "test 1 2 3",
				},
			},
			WantError: nil,
		},
		{
			IP:            "0::1",
			Comment:       "test 1 2 3",
			PriorContents: "",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("::1"),
						Mask: net.CIDRMask(128, 128),
					},
					Comment: "test 1 2 3",
				},
			},
			WantError: nil,
		},
	}

	tempName, err := getTempFilename()
	if err != nil {
		t.Errorf("creating temp file: %s", err)
		return
	}

	recTime := time.Now()

	for _, test := range tests {
		if err := ioutil.WriteFile(tempName, []byte(test.PriorContents),
			0644); err != nil {
			t.Errorf("unable to write to file: %s: %s: %s", tempName,
				test.PriorContents, err)
			continue
		}

		err := RecordIP(tempName, test.IP, test.Comment, recTime)
		if !errorsEqual(err, test.WantError) {
			t.Errorf("RecordIP(%s, %s, %s, %s) = error %s, wanted error %s", tempName,
				test.IP, test.Comment, recTime, err, test.WantError)
			_ = os.Remove(tempName)
			continue
		}

		if err != nil {
			_ = os.Remove(tempName)
			continue
		}

		recs, err := LoadCIDRsFromFile(tempName)
		if !errorsEqual(err, test.WantError) {
			t.Errorf("LoadCIDRsFromFile() error = %s, wanted %s", err, test.WantError)
			_ = os.Remove(tempName)
			continue
		}

		if err := os.Remove(tempName); err != nil {
			t.Fatalf("error removing temporary file: %s: %s", tempName, err)
		}

		// Add time to last record
		test.Records[len(test.Records)-1].Comment = fmt.Sprintf("%s @ %s",
			test.Records[len(test.Records)-1].Comment, recTime.Format(time.RFC1123))

		if err := recordsEqual(recs, test.Records); err != nil {
			t.Errorf("records = %+v, wanted %+v. mismatch is: %s", recs, test.Records,
				err)
			continue
		}
	}
}

func TestWriteFull(t *testing.T) {
	tests := []struct {
		Input string
	}{
		{"hi"},
		{""},
	}

	for _, test := range tests {
		fh, err := ioutil.TempFile("", "test")
		if err != nil {
			t.Errorf("TempFile(\"\", \"test\") = error %s", err)
			return
		}

		if err := writeFull(fh, test.Input); err != nil {
			t.Errorf("writeFull(fh, %s) = error %s", test.Input, err)
			_ = fh.Close()
			_ = os.Remove(fh.Name())
			continue
		}

		if err := fh.Close(); err != nil {
			t.Errorf("writeFull: close: %s", err)
			_ = os.Remove(fh.Name())
			return
		}

		buf, err := ioutil.ReadFile(fh.Name())
		if err != nil {
			t.Errorf("writeFull: reading file back: %s", err)
			_ = os.Remove(fh.Name())
			return
		}

		if string(buf) != test.Input {
			t.Errorf("writeFull: read back different than wrote: %s vs %s", buf,
				test.Input)
			_ = os.Remove(fh.Name())
			continue
		}

		if err := os.Remove(fh.Name()); err != nil {
			t.Errorf("writeFull: remove: %s", err)
			return
		}
	}
}

func TestLoadCIDRsFromFile(t *testing.T) {
	tests := []struct {
		Contents  string
		Records   []Record
		WantError error
	}{
		{
			Contents:  "",
			Records:   []Record{},
			WantError: nil,
		},
		{
			Contents: "# test\n192.168.1.0/24\n",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
					Comment: "test",
				},
			},
			WantError: nil,
		},
		{
			Contents: "192.168.1.0/24\n",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
				},
			},
			WantError: nil,
		},
		{
			Contents: "\n192.168.1.0/24\n\n",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
				},
			},
			WantError: nil,
		},
		{
			Contents: "# test 1 2\n192.168.1.0/24\n# test 3 4\n192.168.0.0/16\n",
			Records: []Record{
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.1.0"),
						Mask: net.CIDRMask(24, 32),
					},
					Comment: "test 1 2",
				},
				{
					Net: &net.IPNet{
						IP:   net.ParseIP("192.168.0.0"),
						Mask: net.CIDRMask(16, 32),
					},
					Comment: "test 3 4",
				},
			},
			WantError: nil,
		},
		{
			Contents:  "# test 1 2\n192.168.1.0/24\njunk\n",
			Records:   []Record{},
			WantError: fmt.Errorf("invalid CIDR address: junk"),
		},
	}

	tempName, err := getTempFilename()
	if err != nil {
		t.Errorf("creating temp file: %s", err)
		return
	}

	// Try when file does not exist.
	_, err = LoadCIDRsFromFile(tempName)
	if !os.IsNotExist(err) {
		t.Errorf("unexpected error when file does not exist: %s", err)
		return
	}

	for _, test := range tests {
		if err := ioutil.WriteFile(tempName, []byte(test.Contents),
			0644); err != nil {
			t.Errorf("unable to write to file: %s: %s: %s", tempName, test.Contents,
				err)
			continue
		}

		recs, err := LoadCIDRsFromFile(tempName)
		if !errorsEqual(err, test.WantError) {
			t.Errorf("LoadCIDRsFromFile() contents = %s, error = %s, wanted error %s",
				test.Contents, err, test.WantError)
			_ = os.Remove(tempName)
			continue
		}

		if err := os.Remove(tempName); err != nil {
			t.Errorf("removing file: %s: %s", tempName, err)
			continue
		}

		if err != nil {
			continue
		}

		if err := recordsEqual(recs, test.Records); err != nil {
			t.Errorf(
				"LoadCIDRsFromFile contents = %s, records = %v, wanted %v. mismatch is: %s",
				test.Contents, recs, test.Records, err)
			continue
		}
	}
}

func errorsEqual(err0, err1 error) bool {
	if err0 == nil && err1 == nil {
		return true
	}
	if err0 == nil && err1 != nil {
		return false
	}
	if err0 != nil && err1 == nil {
		return false
	}
	s0 := fmt.Sprintf("%s", err0)
	s1 := fmt.Sprintf("%s", err1)
	return s0 == s1
}

func recordsEqual(recs0, recs1 []Record) error {
	if recs0 == nil && recs1 == nil {
		return nil
	}
	if recs0 == nil && recs1 != nil {
		return fmt.Errorf("one nil, one not")
	}
	if recs0 != nil && recs1 == nil {
		return fmt.Errorf("one nil, one not")
	}

	if len(recs0) != len(recs1) {
		return fmt.Errorf("record count mismatch: %d vs %d", len(recs0), len(recs1))
	}

	for i := range recs0 {
		if recs0[i].Net.String() != recs1[i].Net.String() {
			return fmt.Errorf("record %d net mismatch: %s vs %s", i,
				recs0[i].Net.String(), recs1[i].Net.String())
		}

		if recs0[i].Comment != recs1[i].Comment {
			return fmt.Errorf("record %d comment mismatch: %s vs %s", i,
				recs0[i].Comment, recs1[i].Comment)
		}
	}

	return nil
}

func getTempFilename() (string, error) {
	fh, err := ioutil.TempFile("", "test")
	if err != nil {
		return "", fmt.Errorf("unable to create temp file: %s", err)
	}

	tempName := fh.Name()

	if err := fh.Close(); err != nil {
		_ = os.Remove(tempName)
		return "", fmt.Errorf("closing file: %s", err)
	}

	if err := os.Remove(tempName); err != nil {
		return "", fmt.Errorf("removing file: %s", err)
	}

	return tempName, nil
}
