package openapi

import (
	"bytes"
	"testing"

	"github.com/swaggest/openapi-go/openapi3"
)

func TestGenerateIsDeterministicAndValidYAML(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("генератор вернул разные результаты")
	}

	var document openapi3.Spec
	if err := document.UnmarshalYAML(first); err != nil {
		t.Fatalf("сгенерирована некорректная спецификация OpenAPI: %v", err)
	}
	if document.Openapi != "3.0.3" {
		t.Fatalf("неожиданная версия OpenAPI: %v", document.Openapi)
	}
	if len(document.Paths.MapOfPathItemValues) == 0 {
		t.Fatal("спецификация не содержит маршрутов")
	}
}
