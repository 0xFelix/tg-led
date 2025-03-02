package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
)

type LoginData struct {
	Password string `json:"Password"`
	Nonce    string `json:"Nonce"`
}

type SetPasswordRequest struct {
	EncryptData string `json:"EncryptData"`
	Name        string `json:"Name"`
	AuthData    string `json:"AuthData"`
}

type SetPasswordResponse struct {
	PStatus     string `json:"p_status"`
	EncryptData string `json:"encryptData"`
}

type SetSessionResponse struct {
	LoginStatus string `json:"LoginStatus"`
}

type SettingsDeviceDataResponse struct {
	LedEnable   string `json:"ledEnable"`
	HTTPSEnable string `json:"httpsEnable"`
}

type SetSettingsDeviceDataRequest struct {
	LedEnable    string `json:"LedEnable"`
	HTTPSEnable  string `json:"HttpsEnable"`
	ActionSelect string `json:"Action_Select"`
}

type tgLed struct {
	client *http.Client
	cipher cipher.AEAD

	// Options set by flags
	address  string
	username string
	password string
	led      bool

	// Values returned by the API
	sessionID     string
	sessionActive bool
	ccmNonce      []byte
	csrfNonce     string
}

const (
	//nolint:gosec
	setPasswordFmt           = "http://%s/php/ajaxSet_Password.php"
	setSessionFmt            = "http://%s/php/ajaxSet_Session.php"
	logoutFmt                = "http://%s/php/logout.php"
	settingsDeviceDataFmt    = "http://%s/php/settings_device_data.php"
	setSettingsDeviceDataFmt = "http://%s/php/ajaxSet_settings_device_data.php"
)

func extractMatch(data string, re *regexp.Regexp) (string, error) {
	match := re.FindStringSubmatch(data)
	const minMatches = 2
	if len(match) < minMatches {
		return "", errors.New("no matches")
	}
	return match[1], nil
}

func (c *tgLed) init() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	c.client = &http.Client{Jar: jar}
	c.parseFlags()

	return nil
}

func (c *tgLed) parseFlags() {
	flag.StringVar(&c.address, "a", "192.168.100.1", "Address of API")
	flag.StringVar(&c.password, "p", "password", "Password for API")
	flag.StringVar(&c.username, "u", "admin", "Username for API")
	flag.BoolVar(&c.led, "l", false, "Turn led on (true) or off (false)")
	flag.Parse()
}

func (c *tgLed) sendRequest(method, url string, body any, csrfNonce bool) ([]byte, error) {
	var reader io.Reader
	if method == http.MethodPost && body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		return nil, err
	}

	if method == http.MethodPost && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrfNonce {
		req.Header.Set("Origin", "http://"+c.address)
		req.Header.Set("csrfNonce", c.csrfNonce)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			fmt.Println("error closing body:", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", res.Status)
	}

	return io.ReadAll(res.Body)
}

func (c *tgLed) config() error {
	data, err := c.sendRequest(http.MethodGet, "http://"+c.address, nil, false)
	if err != nil {
		return err
	}
	sData := string(data)

	c.sessionID, err = extractMatch(sData, regexp.MustCompile(`var currentSessionId = '(.*)';`))
	if err != nil {
		return err
	}

	nonActiveSession, err := extractMatch(sData, regexp.MustCompile(`var nonActiveSession = '(.*)';`))
	if err != nil {
		return err
	}
	if nonActiveSession == "" {
		nonActiveSession = "0"
	}
	c.sessionActive, err = strconv.ParseBool(nonActiveSession)
	if err != nil {
		return err
	}

	myIv, err := extractMatch(sData, regexp.MustCompile(`var myIv = '(.*)';`))
	if err != nil {
		return err
	}
	c.ccmNonce, err = hex.DecodeString(myIv)
	if err != nil {
		return err
	}

	mySalt, err := extractMatch(sData, regexp.MustCompile(`var mySalt = '(.*)';`))
	if err != nil {
		return err
	}
	salt, err := hex.DecodeString(mySalt)
	if err != nil {
		return err
	}

	const iterations = 1000
	const keyLen = 16
	key, err := pbkdf2.Key(sha256.New, c.password, salt, iterations, keyLen)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	const tagSize = 16
	const nonceSize = 8
	c.cipher, err = ccm.NewCCM(block, tagSize, nonceSize)

	return err
}

func (c *tgLed) login() error {
	c.csrfNonce = "undefined"

	loginData := LoginData{
		Password: c.password,
		Nonce:    c.sessionID,
	}
	loginDataBytes, err := json.Marshal(loginData)
	if err != nil {
		return err
	}

	const additionalData = "loginPassword"
	req := SetPasswordRequest{
		EncryptData: hex.EncodeToString(c.cipher.Seal(nil, c.ccmNonce, loginDataBytes, []byte(additionalData))),
		AuthData:    additionalData,
		Name:        "admin",
	}

	res, err := c.sendRequest(http.MethodPost, fmt.Sprintf(setPasswordFmt, c.address), req, true)
	if err != nil {
		return err
	}

	var passwordResponse SetPasswordResponse
	err = json.Unmarshal(res, &passwordResponse)
	if err != nil {
		return err
	}

	if passwordResponse.PStatus != "AdminMatch" {
		return errors.New("login failed (wrong password?)")
	}

	data, err := hex.DecodeString(passwordResponse.EncryptData)
	if err != nil {
		return err
	}

	nonce, err := c.cipher.Open(nil, c.ccmNonce, data, []byte(("nonce")))
	if err != nil {
		return err
	}
	c.csrfNonce = string(nonce)

	if !c.sessionActive {
		if err := c.setSession(); err != nil {
			return err
		}
	}

	return nil
}

func (c *tgLed) setSession() error {
	res, err := c.sendRequest(http.MethodPost, fmt.Sprintf(setSessionFmt, c.address), nil, true)
	if err != nil {
		return err
	}

	var sessionResponse SetSessionResponse
	if err := json.Unmarshal(res, &sessionResponse); err != nil {
		return err
	}

	if sessionResponse.LoginStatus != "yes" {
		return errors.New("login status not yes")
	}

	return nil
}

func (c *tgLed) logout() error {
	_, err := c.sendRequest(http.MethodPost, fmt.Sprintf(logoutFmt, c.address), nil, true)
	return err
}

func (c *tgLed) setLed() error {
	res, err := c.sendRequest(http.MethodGet, fmt.Sprintf(settingsDeviceDataFmt, c.address), nil, true)
	if err != nil {
		return err
	}

	var deviceDataResponse SettingsDeviceDataResponse
	err = json.Unmarshal(res, &deviceDataResponse)
	if err != nil {
		return err
	}

	req := SetSettingsDeviceDataRequest{
		LedEnable:    strconv.FormatBool(c.led),
		HTTPSEnable:  deviceDataResponse.HTTPSEnable,
		ActionSelect: "storeDeviceData",
	}

	res, err = c.sendRequest(http.MethodPost, fmt.Sprintf(setSettingsDeviceDataFmt, c.address), req, true)
	if err != nil {
		return err
	}

	if !strings.Contains(string(res), "PASS") {
		return errors.New("failed to set led")
	}

	return nil
}

func main() {
	c := tgLed{}
	if err := c.init(); err != nil {
		log.Fatal(err)
	}

	if err := c.config(); err != nil {
		log.Fatal(err)
	}

	if err := c.login(); err != nil {
		log.Fatal(err)
	}

	if err := c.setLed(); err != nil {
		log.Fatal(err)
	}

	if err := c.logout(); err != nil {
		log.Fatal(err)
	}
}
