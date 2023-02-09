package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	// "encoding/json"

	// "log"
	// "time"
	"samzhangjy/go-blog/models"

	"github.com/gin-gonic/gin"

	"github.com/golang-jwt/jwt"
	// "github.com/gorilla/handlers"
	// "github.com/gorilla/mux"
	// "github.com/jinzhu/gorm"
	// _ "github.com/jinzhu/gorm/dialects/postgres"
	"reflect"

	"golang.org/x/crypto/bcrypt"
)

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"token"`
}

type CreateUser struct {
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

type SignInType struct {
	Email    string `gorm:"unique" json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte(os.Getenv("JWT_SECRET"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		// fmt.Errorf("Something went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func SignUp(c *gin.Context) {

	var input CreateUser
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userExist models.User

	if err1 := models.DB.Where("email = ?", input.Email).First(&userExist).Error; err1 == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err1.Error()})
		return
	}

	var err error
	var password string
	password, err = GeneratehashPassword(input.Password)

	if err != nil {
		log.Fatalln("error in password hash")
	}
	user := models.User{Email: input.Email, Password: password, Role: input.Role}
	models.DB.Create(&user)

	c.JSON(http.StatusOK, gin.H{"data": user})
}

func SignIn(c *gin.Context) {

	var input SignInType
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userExist models.User

	if err1 := models.DB.Where("email = ?", input.Email).First(&userExist).Error; err1 != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err1.Error()})
		return
	}

	// c.JSON(http.StatusOK, gin.H{"data": input.Email})

	check := CheckPasswordHash(input.Password, userExist.Password)

	if !check {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Password doesn't match"})
		return
	}

	validToken, err := GenerateJWT(userExist.Email, userExist.Role)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "can't generate token"})
		return
	}

	var token Token
	token.Email = input.Email
	token.Role = userExist.Role
	token.TokenString = validToken

	c.JSON(http.StatusOK, gin.H{"data": token})

}

func FindUsers(c *gin.Context) {
	var users []models.User
	models.DB.Find(&users)
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func DeleteUser(c *gin.Context) {
	var user models.User
	if err := models.DB.Where("id = ?", c.Param("id")).First(&user).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "record not found"})
		return
	}

	models.DB.Delete(&user)
	c.JSON(http.StatusOK, gin.H{"data": "success"})
}

func Auth(key string) (string, error) {
	var mySigningKey = []byte(os.Getenv("JWT_SECRET"))

	token, err := jwt.Parse(key, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("Unexpected signing method")
	}

	if token.Valid == false {
		return "", fmt.Errorf("Unexpected signing method")
	}
	fmt.Println("isvalid")
	fmt.Println(token.Valid)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
		return "true", nil
	} else {
		return "", fmt.Errorf("Unexpected signing method")
	}

	// c.JSON(http.StatusOK, gin.H{"data": token.Valid})
}

func Checking(c *gin.Context) {
	var mySigningKey = []byte(os.Getenv("JWT_SECRET"))
	fmt.Println(reflect.TypeOf(c.GetHeader("Authorization")[7:]))

	token, err := jwt.Parse(c.GetHeader("Authorization")[7:], func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}

	c.JSON(http.StatusOK, gin.H{"data": token.Valid})
}

// func IsAuthorize(handler http.HandlerFunc) http.HandlerFunc {
// 	return func(c *gin.Context) {
// 		var mySigningKey = []byte("secretkey")
// 		token, err := jwt.Parse(c.GetHeader("Authorization")[7:], func(token *jwt.Token) (interface{}, error) {
// 			// Don't forget to validate the alg is what you expect:
// 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 			}

// 			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
// 			return mySigningKey, nil
// 		})

// 		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
// 			handler.ServeHTTP(w, r)
// 			return
// 		}

// 		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "record not found"})
// 		return
// 	}
// }

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Header["Token"] == nil {
			var err Error
			err = SetError(err, "No Token Found")
			json.NewEncoder(w).Encode(err)
			return
		}

		var mySigningKey = []byte(os.Getenv("JWT_SECRET"))

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing token.")
			}
			return mySigningKey, nil
		})

		if err != nil {
			var err Error
			err = SetError(err, "Your Token has been expired.")
			json.NewEncoder(w).Encode(err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["role"] == "member" {
				r.Header.Set("Role", "admin")
				handler.ServeHTTP(w, r)
				return

			} else if claims["role"] == "user" {
				r.Header.Set("Role", "user")
				handler.ServeHTTP(w, r)
				return

			}
		}
		// var reserr Error
		// reserr = SetError(reserr, "Not Authorized.")
		json.NewEncoder(w).Encode(err)
	}
}
