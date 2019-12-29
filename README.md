# Snyk Go Client

Golang client library for [Snyk](https://snyk.docs.apiary.io/#).

## Install

```console
$ go get -u -v github.com/picatz/snyk
...
```

## Usage

```go
package main

import (
    "fmt"
    "context"

    "github.com/hashicorp/security-tools/libraries/go/snyk"
)

func main() {
    client, _ := snyk.NewClient(snyk.ClientOptionTokenFromEnv("SNYK_TOKEN"))

    var (
        orgID = "..."
        ctx   = context.Background()
    )

    projects, _ := client.OrganizationProjects(ctx, orgID)

    for _, project := range projects {
        cves, _ := client.ProjectCVEs(ctx, orgID, project.ID, nil)
        fmt.Println(fmt.Sprintf("%s:%s has %d CVEs", project.ID, project.Name, len(cves)))
    }
}
```
