package snyk

import (
	"context"
	"testing"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(WithTokenFromEnv("SNYK_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Organizations(context.TODO())

	if err == nil {
		t.Log("Expected an error because my plan is not entitled for api access.")
	}
}
