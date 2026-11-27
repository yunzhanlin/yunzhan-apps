package appcatalog
import("crypto/sha256";"fmt";"flag";"path/filepath";"runtime";"testing")
var activeFortyRoot=flag.String("active40-registry-root","","actual current40 signed publication root")
var activeFortyReaderMode=flag.String("active40-reader-mode","","exact current handler or retained reader refusal")
func TestActiveFortySignedManifestABI(t *testing.T){
 if *activeFortyReaderMode!="current"&&*activeFortyReaderMode!="retained"{t.Fatal("explicit exact reader mode required")}
 if runtime.GOOS!="linux"||*activeFortyRoot==""{t.Fatal("Actual native Linux and explicit current publication required")}
 root,err:=filepath.Abs(*activeFortyRoot);if err!=nil{t.Fatal(err)}
 raw,err:=boundedRead(filepath.Join(root,"signatures/catalog-v1.bundle.json"),3*maxCatalogBytes);if err!=nil{t.Fatal(err)}
 var bundle catalogBundle;if err=strictJSON(raw,&bundle);err!=nil{t.Fatal(err)}
 client:=NewRegistryClient();catalog,err:=client.verifyCatalog([]byte(bundle.Catalog),[]byte(bundle.Signature));if err!=nil||len(catalog.Apps)!=40{t.Fatal("actual original-key current40 catalogue",err)}
 retired:=map[string]bool{"php-52":true,"php-53":true,"php-54":true,"php-55":true,"php-56":true,"php-70":true,"php-71":true,"php-72":true,"php-73":true,"php-74":true};ids:=map[string]bool{}
 for _,item:=range catalog.Apps{if retired[item.ID]||ids[item.ID]{t.Fatal("retired or duplicate app",item.ID)};ids[item.ID]=true;t.Run(item.ID,func(t *testing.T){
  if item.PackageURL!=client.BaseURL+"/dist/apps/"+item.ID+"/"+item.Version+"/manifest.json"{t.Fatal("noncanonical actual channel URL")}
  body,err:=boundedRead(filepath.Join(root,"dist/apps",item.ID,item.Version,"manifest.json"),maxManifestBytes);if err!=nil{t.Fatal(err)};if fmt.Sprintf("%x",sha256.Sum256(body))!=item.SHA256{t.Fatal("actual signed package bytes changed")}
  if *activeFortyReaderMode=="retained"&&item.ID=="mobile"&&item.Version=="1.4.0"{var original Manifest;if err:=strictJSON(body,&original);err!=nil{t.Fatal(err)};if original.ID!="mobile"||original.Version!="1.4.0"||original.Delivery.Provider!="panel-module"||original.Delivery.Target!="mobile-pwa"||original.Delivery.ManageRoute!="app-modules"||len(original.RequiredPanelFeatures)!=1||original.RequiredPanelFeatures[0]!="mobile-web-workspace-v140"{t.Fatal("foreign manifest cannot qualify older reader refusal")};if _,err:=client.verifyManifestData(item,body);err==nil{t.Fatal("retained reader must refuse unsupported mobile140")};return}
  manifest,err:=client.verifyManifestData(item,body);if err!=nil||manifest.ID!=item.ID||manifest.Version!=item.Version{t.Fatal("actual current SDK rejects signed manifest",item.ID,err)}
 })}
 for _,id:=range []string{"php-80","php-81","php-82","php-83","php-84","php-85"}{if !ids[id]{t.Fatal("retained PHP8 app missing",id)}}
}
