package main

import (
	// "encoding/json"
	"fmt"
	"net/http"
	"strings"
	// "strings"
	"time"
	fiber "github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	// 	"gorm.io/driver/postgres"
	// 	"gorm.io/gorm"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

var users = make(map[string]User)
var secretKey = []byte("rohith.....")

func main(){
	app:=fiber.New()
	// Un Protected routes                                                   
	app.Post("/register",Register)
	app.Post("/login",Login)
	app.Get("/ping", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "pong"})
	})	
	// Protected routes
	api:= app.Group("/api", protected)
	api.Get("api/profile", getprofile)
	app.Listen(":3000")
}

func getprofile(c *fiber.Ctx)error{
	userClaims := c.Locals("user").(jwt.MapClaims)
	username,ok := userClaims["username"].(string)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
	}	
		return c.JSON(fiber.Map{
		"message": "Welcome to your profile",
		"username": username,	
	})

}

func protected(c *fiber.Ctx) error{
	tokenString:= c.Get("Authorization")
	if tokenString ==""{
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
	} 

	parts:= strings.Split(tokenString, " ")
	if len(parts)!= 2 || parts[0]!="Bearer"{
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token format"})
	}

	tokenString= parts[1]
	if err:=verifyToken(c, tokenString);err!=nil{
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}
	return c.Next()
}


func Register(c *fiber.Ctx) error{
	var user User
	if err:=c.BodyParser(&user);err!=nil{
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}
	if _, exists := users[user.Username];exists{
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
	}

	users[user.Username]=user
	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func extactSecretToken(token *jwt.Token)(interface{}, error){
	return secretKey, nil
}

// extactSecretToken is a function that extracts the secret key from the token.
func verifyToken(c *fiber.Ctx,tokenString string) error{
	token,err:=jwt.Parse(tokenString,extactSecretToken)
	if err!=nil{
		return err                                                      
	}
	if !token.Valid{
		return fmt.Errorf("invalid token")
	}
	claims,ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("invalid token claims")
	}
	userClaims, ok := claims["username"].(string)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}
	c.Locals("user", claims) // Store the claims in the context for later use
	c.Locals("username", userClaims) // Store the username in the context for er
	return nil
}

func Createtoken(username string) (string,error){
	token:=jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":username,
		"exp":  time.Now().Add(time.Hour *24).Unix(),	
	})

	tokenString,err:=token.SignedString(secretKey)
	if err!=nil{
		return "",err
	}
	return tokenString, nil

}


func Login(c *fiber.Ctx) error{
	var user User
	if err:= c.BodyParser(&user);
	err!=nil{
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}
	existingUser, exists:=users[user.Username];
	if !exists || existingUser.Password!=user.Password{
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}


	 tokenString, err:=Createtoken(user.Username)
	 if err!=nil{
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not create token"})	
	 }

	 return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"token": tokenString,
	 })
}


