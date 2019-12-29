package snyk

import (
	"context"
	"fmt"
	"testing"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(WithTokenFromEnv("SNYK_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}

	result := map[string]interface{}{}
	err = client.RawQuery(context.TODO(), "GET", "orgs", nil, nil, &result)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(result)
	t.Log(result)
}
