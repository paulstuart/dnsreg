package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	dns_add = `update add %s.%s %d IN A %s
send
update add %s.in-addr.arpa %d PTR %s.%s.
send
`
	dns_del = `update delete %s.%s IN A %s
send
update delete %s.in-addr.arpa PTR %s.%s.
send
`
	path = "/register/"
)

var (
	domain string
	port   = 8888
	ttl    = 38400
	valid  = regexp.MustCompile("[a-zA-Z0-9-]+")
	ipAddr = myIP()
)

func init() {
	flag.IntVar(&port, "port", port, "bind to this port")
	flag.IntVar(&ttl, "ttl", ttl, "time to live")
}

func reverseAddr(addr string) string {
	bits := strings.Split(addr, ".")
	return bits[3] + "." + bits[2] + "." + bits[1] + "." + bits[0]
}

func dnsCommand(text string) error {
	cmd := exec.Command("nsupdate")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(text)); err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		return err
	}
	stdin.Close()
	err = cmd.Wait()
	bad, _ := ioutil.ReadAll(stderr)
	stderr.Close()
	errorText := string(bad)
	if len(errorText) > 0 {
		fmt.Println("error:", errorText)
	}
	return err
}

func dnsAdd(hostname, ip string) error {
	if addrs, err := net.LookupHost(hostname); err == nil {
		return fmt.Errorf("%s is already assigned to: %s", hostname, strings.Join(addrs, ","))
	}
	if hosts, err := net.LookupAddr(ip); err == nil {
		return fmt.Errorf("%s is already assigned to: %s", ip, strings.Join(hosts, ","))
	}
	txt := fmt.Sprintf(dns_add, hostname, domain, ttl, ip, reverseAddr(ip), ttl, hostname, domain)
	return dnsCommand(txt)
}

func dnsDelete(hostname, ip string) error {
	if _, err := net.LookupHost(hostname); err != nil {
		return err
	}
	txt := fmt.Sprintf(dns_del, hostname, domain, ip, reverseAddr(ip), hostname, domain)
	return dnsCommand(txt)
}

// get ip of this host
func myIP() string {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !strings.HasPrefix(ipnet.String(), "127.") && strings.Index(ipnet.String(), ":") == -1 {
			return strings.Split(ipnet.String(), "/")[0]
		}
	}
	return ""
}

// get ip of http request
func RemoteHost(r *http.Request) string {
	if remote_addr := r.Header.Get("X-Forwarded-For"); len(remote_addr) > 0 {
		return remote_addr
	}
	remote_addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "REMOTE ADDR ERR:", err)
	}
	if len(remote_addr) > 0 && remote_addr[0] == ':' {
		remote_addr = ipAddr
	}
	return remote_addr
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Path

	// validate request

	if len(hostname) == 0 {
		http.Error(w, "no hostname specified", http.StatusInternalServerError)
		return
	}
	if dot := strings.Index(hostname, "."); dot > 0 {
		given := hostname[dot+1:]
		if len(given) > 0 && given != domain {
			msg := fmt.Sprintf("invalid domain: %s. must be: %s", given, domain)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		hostname = hostname[:dot]
		if !valid.MatchString(hostname) {
			http.Error(w, "invalid hostname: "+hostname, http.StatusBadRequest)
			return
		}
	}
	if hostname == "localhost" {
		http.Error(w, "invalid hostname: "+hostname, http.StatusBadRequest)
		return
	}
	ip := RemoteHost(r)
	if r.Method == "POST" {
		if err := dnsAdd(hostname, ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "added hostname '%s' for %s\n", hostname, ip)
	} else if r.Method == "DELETE" {
		if err := dnsDelete(hostname, ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "deleted hostname '%s' for %s\n", hostname, ip)
	}
}

func badPath(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "invalid path: "+r.URL.Path, http.StatusInternalServerError)
}

func main() {
	flag.Parse()
	out, err := exec.Command("hostname", "-d").Output()
	if err != nil {
		panic(err)
	}

	domain = strings.TrimSpace(string(out))
	if len(domain) == 0 {
		panic("no domain via hostname: " + domain)
	}

	http.Handle(path, http.StripPrefix(path, http.HandlerFunc(RegisterHandler)))
	http.HandleFunc("/", badPath)
	fmt.Printf("listen: http://%s:%d\n", ipAddr, port)
	listenAddr := fmt.Sprintf(":%d", port)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		panic("ListenAndServe: " + err.Error())
	}

}
