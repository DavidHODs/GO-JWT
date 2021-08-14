package controllers

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/DavidHODs/GO-JWT/database"
	"github.com/DavidHODs/GO-JWT/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)


func Register(c *fiber.Ctx) error {
	var data map[string]string

	err := c.BodyParser(&data); if err != nil {
		return err
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

	user := models.User{
		Name: data["name"],
		Email: data["email"],
		Password: password,
	}

	database.DB.Create(&user)

    return c.JSON(user)
}


func Login(c *fiber.Ctx) error {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error Loading .env File")
	}

	SecretKey := os.Getenv("SecretKey")

	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user models.User

	database.DB.Where("email = ?", data["email"]).First(&user)

	if user.Id == 0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message":"user not found",
		})
	} else {
		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON((fiber.Map{
				"mesage":"incorrect password",
			}))
		}

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
			Issuer: strconv.Itoa(int(user.Id)),
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		})

		token, err := claims.SignedString([]byte(SecretKey))

		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return c.JSON(fiber.Map{
				"message": "Could not log in",
			})
		}

		cookie := fiber.Cookie{
			Name: "jwt",
			Value:token,
			Expires: time.Now().Add(time.Hour * 24),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message":"success",
		})
	}
}


func User(c *fiber.Ctx) error {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error Loading .env File")
	}

	SecretKey := os.Getenv("SecretKey")

	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message":"unauthenticated",
		})
	}
	
	claims := token.Claims.(*jwt.StandardClaims)

	var user models.User

	database.DB.Where("Id = ?", claims.Issuer).First(&user)

	return c.JSON(user)
}


func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name: "jwt",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"message":"success",
	})
}