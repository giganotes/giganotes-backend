package giganotes

import (
	"fmt"
	"testing"
)

func TestFindLinks(t *testing.T)  {
	result, _ := downloadImageAsBase64("https://github.githubassets.com/images/modules/logos_page/Octocat.png")
	fmt.Println(result)
}