package authenticator

import (
	"crypto/ed25519"
	"errors"
	"time"

	"log"

	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/golang-jwt/jwt"
	"github.com/mitchellh/mapstructure"
)

func ValidateTokenClaim(token string, secret ed25519.PublicKey, ttl time.Duration) (utils.IClaims, error) {
	jwtClaims, err := ValidateToken(token, secret, ttl)
	if err != nil {
		return nil, err
	}

	return GetClaimsFromJwt(jwtClaims)
}

func ValidateToken(token string, secret ed25519.PublicKey, ttl time.Duration) (*jwt.MapClaims, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}

	parseHandle := func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}

	jwtToken, err := parser.Parse(token, parseHandle)
	if err != nil {
		log.Println(err.Error())
		return nil, errors.New("401")
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return nil, errors.New("402")
	}

	createdAt, ok := claims["crat"].(float64)
	if !ok {
		return nil, errors.New("403")
	}

	createdAt = createdAt + float64(ttl.Milliseconds())
	now := float64(time.Now().Unix())
	if createdAt < now {
		return nil, errors.New("404")
	}
	return &claims, err
}

func GetClaimsFromJwt(claims *jwt.MapClaims) (utils.IClaims, error) {
	result := &utils.Claims{}
	userClaims := (*claims)["user"]
	if err := mapstructure.WeakDecode(userClaims, &result); err != nil {
		log.Println(err.Error())
		return nil, errors.New("405")
	}

	return result, nil
}

func GenerateToken(secret ed25519.PrivateKey, hash string, claims interface{}, externalData interface{}) (string, error) {
	jwtClaims := jwt.MapClaims{}
	jwtClaims["crat"] = time.Now().Unix()

	if claims != nil {
		jwtClaims["user"] = claims
	}

	if hash != "" {
		jwtClaims["hash"] = hash
	}

	if externalData != nil {
		jwtClaims["ext"] = externalData
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwtClaims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		log.Println(err.Error())
		return "", errors.New("406")
	}
	return tokenString, nil
}
