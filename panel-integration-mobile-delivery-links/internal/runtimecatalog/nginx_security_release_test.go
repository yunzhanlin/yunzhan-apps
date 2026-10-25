package runtimecatalog

import "testing"

func TestNginxSecurityReleaseIsAdditiveAndImmutable(t *testing.T) {
	r, ok := Find("nginx-1.30.6")
	if !ok || r.ID != "nginx-1.30.6" || r.Family != "nginx" || r.Version != "1.30.6" || r.Series != "1.30" || r.Channel != "stable" || r.URL != "https://nginx.org/download/nginx-1.30.6.tar.gz" || r.SHA256 != "3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8" {
		t.Fatal("new release is not the independent official signed artifact", r)
	}
	if Nginx[0] != r {
		t.Fatal("fresh runtime choice did not prefer the current stable release")
	}
	for id, pin := range map[string]string{"nginx-1.30.4": "4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b", "nginx-1.31.5": "e951607d534836624bd36b6b45a71dbfb055237deae3738da6bbf3270dada279"} {
		old, ok := Find(id)
		if !ok || old.SHA256 != pin || old.URL != "https://nginx.org/download/"+id+".tar.gz" {
			t.Fatal("historical installation identity was rewritten", id)
		}
	}
	for _, id := range []string{"nginx-latest", "nginx-1.30.6?x=1", "NGINX-1.30.6", "nginx-1.30.6/../other", "nginx-1.30.6-preview"} {
		if _, ok := Find(id); ok {
			t.Fatal("runtime alias or mutable source accepted", id)
		}
	}
}
