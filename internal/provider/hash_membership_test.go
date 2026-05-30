package provider

import (
	"reflect"
	"testing"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestExtractSHA256sFromPackageXML(t *testing.T) {
	raw := []byte(`<AirlockCapture>
		<filewrite sha256="` + hashB + `">
			<sha256>` + hashA + `</sha256>
			<sha512>` + hashC + hashC + `</sha512>
		</filewrite>
		<fileload><sha256>` + hashA + `</sha256></fileload>
	</AirlockCapture>`)

	got := extractSHA256s(raw)
	want := []string{hashA, hashB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected hashes: got %#v want %#v", got, want)
	}
}

func TestParseHashMembershipImportID(t *testing.T) {
	targetID, hashes, id, err := parseHashMembershipImportID("application", "application:1700000000:"+hashB+","+hashA)
	if err != nil {
		t.Fatal(err)
	}
	if targetID != "1700000000" {
		t.Fatalf("unexpected target ID: %s", targetID)
	}
	if want := []string{hashA, hashB}; !reflect.DeepEqual(hashes, want) {
		t.Fatalf("unexpected hashes: got %#v want %#v", hashes, want)
	}
	if want := "application:1700000000:" + hashA + "," + hashB; id != want {
		t.Fatalf("unexpected normalized ID: got %q want %q", id, want)
	}
}

func TestParseHashMembershipImportIDRejectsWrongKind(t *testing.T) {
	_, _, _, err := parseHashMembershipImportID("baseline", "application:1700000000:"+hashA)
	if err == nil {
		t.Fatal("expected kind mismatch error")
	}
}

func TestHashesSubsetNormalizesInput(t *testing.T) {
	if !hashesSubset([]string{hashA, hashB}, []string{hashB, stringsToUpper(hashA)}) {
		t.Fatal("expected hashes to match case-insensitively")
	}
	if hashesSubset([]string{hashA}, []string{hashA, hashB}) {
		t.Fatal("expected missing hash to fail subset check")
	}
}

func stringsToUpper(in string) string {
	out := []byte(in)
	for i, b := range out {
		if b >= 'a' && b <= 'z' {
			out[i] = b - 'a' + 'A'
		}
	}
	return string(out)
}
