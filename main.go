package main

import (
	"samzhangjy/go-blog/controllers"
	"samzhangjy/go-blog/models"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/itsjamie/gin-cors"

	"log"

	// "fmt"
	// "os"

	"github.com/joho/godotenv"
)

func Config() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}

func main() {
	router := gin.Default()
	router.Use(cors.Middleware(cors.Config{
		Origins:         "*",
		Methods:         "GET, PUT, POST, DELETE, PATCH",
		RequestHeaders:  "Origin, Authorization, Content-Type",
		ExposedHeaders:  "",
		MaxAge:          50 * time.Second,
		Credentials:     false,
		ValidateHeaders: false,
	}))
	Config()
	models.ConnectDatabase()

	router.POST("/posts", controller.CreatePst)
	router.GET("/posts", controller.FindPosts)
	router.GET("/posts/:id", controller.FindPost)
	router.PATCH("/posts/:id", controller.UpdatePost)
	router.DELETE("/posts/:id", controller.DeletePost)

	router.POST("/signup", controller.SignUp)
	router.GET("/env", controller.Env)

	router.POST("/signin", controller.SignIn)

	router.GET("/user", controller.FindUsers)
	router.GET("/check", controller.Checking)

	router.DELETE("/user/:id", controller.DeleteUser)

	router.Run("localhost:8080")

}
