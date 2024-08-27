package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	appID   = "M0qbcDRl134AduJb"
	privKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCt13P/QwD54uP6
iWZldaqTlGzcktYtOv+t6GWlzX5beM/nFIlNwJVSSYMJURvXlzBW38AC4dbrx7AB
Be7vRfebyW8F4ghyXcz7nMfQk0kIV4aVe1q1nfpsGYY3rjboR1bQgo36cw0G/Vh6
gN5H1Y7Uuc16UROIqWdrBcdvY/vEcG//a1erMPipTCuANQW/C04rbxDR01z+lOQg
BYnZo8myvYpM1PXFeausWOpuNTngs1t5nqcAOAKgmWEjfc52graBdfCcih4dcn73
xzM3lu9JdWOaN+4RN2jT9C68Bq3lNzGS+4lzhxZObvJjKkeq9B1cRoGGiASXntvG
hxtQUaKdAgMBAAECggEAG5ND5NIgaIL+E3K8xGFQJ81xII1GM1yFdspDaB6FlEWW
AkYMAEJegp6t43TIjCqA/Mwh7WhyKr+9LRxff02Y7k7whn1em6Lsw14Q2rFSR2Qi
3A6kyo7+9ytr/TnBn0IZr5orTUv3XWF4fyN2nuxtlf7MbOz0F/HPOXcW4JYlN06K
KgP8LXpn5C0Yhmz9o3Df4fKlEWb4se80b85i82+Qqak7rlwJNAu6rrMLN6qbMgsA
rwoS1pY948qySIEn3riR+QpTvTUcUUuKBNPzHym8u1kh0s/G4SUfeYR8JAfhxPok
zqXycf/wuAykDgCO6WSdS8cepILsgmIfYctq5L2tvQKBgQDg/sCSCPi7bMs8Z1uj
MWnOApRkWjrB+Rs0RAAeLJyUrr/LfJc6OPAhDyuS9hhRccmC7O5FI8c/92sGNSZO
T7YIJy2qScJS5BWwkE1dQ/yPKUPs++qUrGeg6zyMPCYVqI9h2DWqXiTHnX0KdnJV
DY1K/CX4A1vmvAArflHKFJWOrwKBgQDFzCMMD1A3KgKWTwuzqNRehnv82jI7/kua
bTn+f5TE8E9Fv1SOEDqKdsBd9glRSiiuTJP3oE+WC+x2nQ7jApjia74jctBb3Xiq
o4OWt+XD8Imo9F7TGH0OabUbUyowcXzk7d52QONWFlxklI1GCh5+5ryvrMBHya1F
09L+qviWcwKBgQCmhAQTUG59j/QOHVSVv8FVhVU7vAeWfX1jvhv0OQIdjANIX0ow
/ejCHs8Z8eZniHYh3qYtJ2CUd9GOg5F5Dcdj21MRn4sg+8sNpI6NQv7NGTY7Uun2
5G3Bi7eA9hcdmmWbfX+iOhCwZ18eejD9v4zdfSXAmwPODT928QMpMvjI4wKBgAHs
8NJnO8KtuAS6lESVeivJZ1+YyDBpU1cXhR8DIvGf3UWyjSIs6kT6zvibMpAGBstb
l30rpFqzlwO4l7KCDfb2UY2Kyph6WXhfyyImfCgiKVTpvBqV/HGtecPgVWLPWAXq
guXnz87AvPmFsLJj2tQlbuTO67hHMFajr0QnafAdAoGBANVOboaCPMOZsIh11z9a
yqCMSNsTxMrTaac01fcSFm3qRtaPZgqC3igXZ86/90M3dmF++3fi6xIsTDapa4cu
fNkp7Z8mL9oq2Jwp3X0Mx3sOB31W6IAPEX9zNjvQ7bSLKwC3Qwrq7cLQdXQg8dFu
VJ1VkGd+VnH2G4QJYsvDoJkQ
-----END PRIVATE KEY-----`
)

// ParsePrivateKey 格式化私钥
func ParsePrivateKey(privkey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privkey))
	if block == nil {
		return nil, errors.New("failed to parse private key")
	}

	// 修改这里
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 如果 PKCS1 解析失败,再尝试 PKCS8 解析
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		tmp, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("parsed key is not an RSA private key")
		}
		privateKey = tmp
	}

	return privateKey, nil

}

// VerifyWithPrivateKey 使用私钥验证签名/解密
func VerifyWithPrivateKey(data, signature string, privkey *rsa.PrivateKey) error {
	signatureBase64, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// 使用私钥解密签名, 将解密后的结果与原始数据进行比较
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, signatureBase64)
	if err != nil {
		logrus.Errorf("DecryptPKCS1v15 failed: %v", err)
		return err
	}
	if !bytes.Equal([]byte(data), decryptedData) {
		return errors.New("signature verification failed")
	}
	return nil
}

func verifySignature(content, signature, timestamp string) bool {
	signText := appID + timestamp + content

	pri, err := ParsePrivateKey(privKey)
	if err != nil {
		logrus.Errorf("ParsePrivateKey failed: %v", err)
		return false
	}
	if err := VerifyWithPrivateKey(signText, signature, pri); err != nil {
		return false
	}
	return true
}

func processWebhook(c *gin.Context) {
	timestamp := c.GetHeader("Timestamp")
	sign := c.GetHeader("Sign")

	signText, _ := io.ReadAll(c.Request.Body)
	if verifySignature(string(signText), sign, timestamp) {
		logrus.Infof("verify sign success, content:%s timestamp:%s signature:%s", string(signText), timestamp, sign)
		c.String(http.StatusOK, "success")
	} else {
		logrus.Infof("verify sign failed, content:%s timestamp:%s signature:%s", string(signText), timestamp, sign)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
	}
}
func main() {
	router := gin.Default()
	router.POST("/webhook", processWebhook)
	router.Run(":3000")
}
