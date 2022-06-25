package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type registerNonceResponse struct {
	Nonce string `json:"nonce"`
}

type registerRequest struct {
	Nonce       string `json:"nonce"`
	Username    string `json:"username"`
	DisplayName string `json:"displayname"`
	Password    string `json:"password"`
	Admin       bool   `json:"admin"`
	MAC         string `json:"mac"`
}

type registerResponse struct {
	AccessToken string `json:"access_token"`
	UserID      string `json:"user_id"`
	HomeServer  string `json:"home_server"`
	DeviceID    string `json:"device_id"`
}

var (
	homeserverURL string
	username      string
	password      string
	displayName   string
	secret        string
)

func init() {
	flag.StringVar(&homeserverURL, "homeserver", "", "Homeserver URL, e.g. https://matrix.org")
	flag.StringVar(&secret, "secret", "", "Matrix homeserver registration shared secret")
	flag.StringVar(&username, "username", "", "Matrix username")
	flag.StringVar(&password, "password", "", "Matrix password")
	flag.StringVar(&displayName, "display-name", "", "Matrix user display name, e.g. 'Michael Bolton'")
}

func main() {
	flag.Parse()

	if homeserverURL == "" ||
		secret == "" ||
		username == "" ||
		password == "" ||
		displayName == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Get nonce value from register endpoint
	res, err := http.Get(fmt.Sprintf("%s/_synapse/admin/v1/register", homeserverURL))
	if err != nil {
		log.Fatalln(err)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	if res.StatusCode != http.StatusOK {
		log.Fatalf("body: %s", string(body))
	}
	nonceRes := &registerNonceResponse{}
	err = json.Unmarshal(body, nonceRes)
	if err != nil {
		log.Fatalln(err)
	}

	// Create registration request + Generate MAC
	regReq := &registerRequest{
		Nonce:       nonceRes.Nonce,
		Username:    username,
		Password:    password,
		DisplayName: displayName,
	}
	setMAC(regReq)

	// Encode registration request as JSON
	reqJSON, err := json.Marshal(regReq)
	err = json.Unmarshal(body, nonceRes)
	if err != nil {
		log.Fatalln(err)
	}
	reqBody := strings.NewReader(string(reqJSON))

	// Make register request
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/_synapse/admin/v1/register", homeserverURL), reqBody)
	if err != nil {
		log.Fatalln(err)
	}
	res, err = http.DefaultClient.Do(req)
	body, err = io.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	if res.StatusCode != http.StatusOK {
		log.Fatalf("failure: %s", string(body))
	}

	// Decode response
	regRes := &registerResponse{}
	err = json.Unmarshal(body, regRes)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("success: %+v", regRes)
}

// setMAC sets the mac field in the matrix shared secret
// register request using the shared secret as the key
//
// See: https://matrix-org.github.io/synapse/latest/admin_api/register_api.html
func setMAC(req *registerRequest) {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(req.Nonce))
	mac.Write([]byte("\u0000"))
	mac.Write([]byte(req.Username))
	mac.Write([]byte("\u0000"))
	mac.Write([]byte(req.Password))
	mac.Write([]byte("\u0000"))
	mac.Write([]byte("notadmin"))

	req.MAC = hex.EncodeToString(mac.Sum(nil))
}
