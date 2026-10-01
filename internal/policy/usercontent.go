package policy

import "strings"

// userContentSuffixes are domains under which arbitrary third parties can create hostnames,
// host content, or run DNS. A wildcard allow rule over any of these lets an agent exfiltrate to
// (or fetch from) an attacker-controlled name, and — because the gateway resolves names itself —
// even a lookup of such a name can carry data out. This is a curated approximation of the private
// section of the Public Suffix List plus common object-storage and tunnelling domains; it is not
// exhaustive, which is why `policy lint` also warns on every wildcard.
var userContentSuffixes = []string{
	// Source hosting / pages
	"github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io", "codeberg.page", "sourceforge.io",
	// Cloud object storage and CDNs
	"s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "storage.googleapis.com", "googleusercontent.com",
	"blob.core.windows.net", "azureedge.net", "azurewebsites.net", "windows.net", "r2.dev", "r2.cloudflarestorage.com",
	"digitaloceanspaces.com", "backblazeb2.com", "wasabisys.com",
	// App platforms
	"vercel.app", "netlify.app", "herokuapp.com", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
	"appspot.com", "onrender.com", "fly.dev", "railway.app", "surge.sh", "glitch.me", "repl.co", "replit.dev",
	"deno.dev", "val.run", "streamlit.app", "hf.space", "run.app", "cloudfunctions.net", "ondigitalocean.app",
	// Tunnels and dynamic DNS (attacker-controlled DNS by design)
	"ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "localtunnel.me",
	"duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "dyndns.org", "dynu.net", "freedns.afraid.org",
	// Blogs, site builders, misc
	"blogspot.com", "wordpress.com", "wixsite.com", "myshopify.com", "weebly.com", "carrd.co", "notion.site",
	"ipfs.io", "dweb.link", "cloudflare-ipfs.com", "nip.io", "sslip.io", "xip.io", "traefik.me",
}

// multiLabelPublicSuffixes are common public suffixes with more than one label. A wildcard whose
// base is exactly one of these ("*.co.uk") would match every registrant under it.
var multiLabelPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "org.nz": true, "net.nz": true, "co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	"co.in": true, "net.in": true, "org.in": true, "com.br": true, "net.br": true, "org.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "com.hk": true, "com.sg": true, "com.tw": true,
	"co.za": true, "co.kr": true, "or.kr": true, "com.mx": true, "com.ar": true, "com.tr": true, "co.il": true,
}

// userContentSuffix returns the listed suffix that base equals or falls under.
func userContentSuffix(base string) (string, bool) {
	for _, s := range userContentSuffixes {
		if base == s || strings.HasSuffix(base, "."+s) {
			return s, true
		}
	}
	return "", false
}
