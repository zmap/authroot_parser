package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TomOnTime/utfutil"
	"go.mozilla.org/pkcs7"
)

const CERT_DIST_POINT = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/"

type Sequence struct {
	Data asn1.RawValue
}

type CTLEntryValue struct {
	Data []byte
}

type CTLEntryAttribute struct {
	Type  asn1.ObjectIdentifier
	Value CTLEntryValue `asn1:"set"`
}

type CTLEntry struct {
	CertFingerprint []byte
	Attributes      []CTLEntryAttribute `asn1:"set"`
}

type CTL struct {
	Signers         []asn1.ObjectIdentifier
	SequenceNumber  *big.Int
	EffectiveDate   time.Time
	DigestAlgorithm pkix.AlgorithmIdentifier
	Entries         []CTLEntry
}

func oidList(data []byte) string {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(data, &oids); err != nil {
		panic(err)
	}
	var s string
	for _, oid := range oids {
		s += fmt.Sprintf(" %s", oid.String())
	}
	return s
}

type PolicyQualifier struct {
	OID  asn1.ObjectIdentifier
	Bits asn1.BitString
}

type CertPolicy struct {
	OID       asn1.ObjectIdentifier
	Qualifier []PolicyQualifier
}

type CertPolicies struct {
	Policies []CertPolicy
}

func policyList(data []byte) string {
	// Wrap policy list in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: data}}
	var der_pol []byte
	var err error
	if der_pol, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	var policies CertPolicies
	if _, err = asn1.Unmarshal(der_pol, &policies); err != nil {
		panic(err)
	}

	var s string
	for _, pol := range policies.Policies {
		if pol.OID.String() == "1.3.6.1.4.1.311.94.1.1" {
			s += " EV Disabled"
		} else {
			s += " " + pol.OID.String()
		}
	}
	return s
}

func msFiletime(data []byte) string {
	switch len(data) {
	case 8:
		return fmt.Sprintf("%v", time.Date(1601, time.January, 1, 0, 0, int(binary.LittleEndian.Uint64(data)/10000000), 0, time.UTC))
	case 0:
		return fmt.Sprintf("Since forever")
	default:
		panic(fmt.Errorf("Unexpected length (%d)", len(data)))
	}
}

func utf16to8(data []byte) string {
	if bytes, err := ioutil.ReadAll(utfutil.BytesReader(data, utfutil.WINDOWS)); err != nil {
		panic(err)
	} else {
		return string(bytes[0 : len(bytes)-1])
	}
}

func main() {
	// Read DER-encoded authroot PKCS#7 file.
	var err error
	var authroot_data []byte
	if authroot_data, err = ioutil.ReadFile(os.Args[1]); err != nil {
		panic(err)
	}

	// Parse the PKCS#7, whose Content is assumed to have type szOID_CTL (1.3.6.1.4.1.311.10.1).
	var p7 *pkcs7.PKCS7
	if p7, err = pkcs7.Parse(authroot_data); err != nil {
		panic(err)
	}

	// Wrap p7.Content in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: p7.Content}}
	var der_ctl []byte
	if der_ctl, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	// Parse the CTL.
	var ctl CTL
	if _, err = asn1.Unmarshal(der_ctl, &ctl); err != nil {
		panic(err)
	}

	for _, entry := range ctl.Entries {
		url := CERT_DIST_POINT + hex.EncodeToString(entry.CertFingerprint) + ".crt"
		resp, err := http.Get(url)

		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		pem := base64.StdEncoding.EncodeToString(body)
		pem = strings.ReplaceAll(pem, "\n", "")
		pem = strings.ReplaceAll(pem, " ", "")
		pem = strings.ReplaceAll(pem, "\t", "")

		fmt.Println("-----BEGIN CERTIFICATE-----")
		for start := 0; start < len(pem); start += 64 {
			next := start + 64
			if next > len(pem) {
				next = len(pem)
			}
			fmt.Println(pem[start:next])
		}
		fmt.Println("-----END CERTIFICATE-----")
	}
}
