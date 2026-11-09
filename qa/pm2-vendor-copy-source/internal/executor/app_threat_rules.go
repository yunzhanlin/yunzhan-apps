package executor

// Original, bounded starter rules. These are specific indicators, not a claim
// of comprehensive threat intelligence or a replacement for a maintained WAF.
const threatIDSOriginalRules = `alert http any any -> $HOME_NET any (msg:"CloudStack HTTP raw traversal indicator"; flow:established,to_server; http.uri.raw; content:"../"; classtype:web-application-attack; sid:9000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"CloudStack HTTP encoded traversal indicator"; flow:established,to_server; http.uri.raw; content:"%2e%2e"; nocase; classtype:web-application-attack; sid:9000002; rev:1;)
alert http any any -> $HOME_NET any (msg:"CloudStack HTTP scanner user agent indicator"; flow:established,to_server; http.user_agent; content:"sqlmap"; nocase; classtype:web-application-attack; sid:9000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"CloudStack HTTP TRACE method observed"; flow:established,to_server; http.method; content:"TRACE"; startswith; endswith; classtype:protocol-command-decode; sid:9000004; rev:1;)
alert http any any -> $HOME_NET any (msg:"CloudStack HTTP shell command indicator"; flow:established,to_server; http.request_body; content:"/bin/sh"; classtype:web-application-attack; sid:9000005; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"CloudStack repeated TCP SYN indicator"; flags:S; flow:stateless; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000006; rev:1;)
`

const threatIDSOriginalRulesLicense = `MIT License

Copyright (c) 2026 Yunzhan contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

const threatIDSOriginalClassifications = `config classification: web-application-attack,Web application risk indicator,1
config classification: protocol-command-decode,Unusual protocol command indicator,3
config classification: attempted-recon,Repeated connection reconnaissance indicator,2
`
const threatIDSOriginalReferences = "# Original starter rules do not use external rule references.\n"

const threatIDSOriginalThresholds = "# Original starter rules have no global suppression overrides.\n"

func threatIDSOriginalRuleFiles() map[string]string {
	return map[string]string{"cloudstack.rules": threatIDSOriginalRules, "LICENSE": threatIDSOriginalRulesLicense, "classification.config": threatIDSOriginalClassifications, "reference.config": threatIDSOriginalReferences, "threshold.config": threatIDSOriginalThresholds}
}
