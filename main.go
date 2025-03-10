package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"time"
)

func connectToDb() *gorm.DB {
	db, err := gorm.Open(postgres.Open("postgresql://baclearn_owner:6HkoqxnmWNa5@ep-bold-scene-a5tudpps-pooler.us-east-2.aws.neon.tech/baclearn?sslmode=require"), &gorm.Config{})

	if err != nil {
		panic(err.Error())
	}

	return db
}
func hashPass(password string) []byte {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 10)

	if err != nil {
		panic(err.Error())
	}

	return hashedPass
}
func comparePassword(hashedPass string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(password))

	return err == nil
}

type User struct {
	ID        int       `json:"id" gorm:"primaryKey;autoIncrement"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Password  string    `json:"password" gorm:"not null"`
	Posts     []Post    `json:"posts" gorm:"foreignKey:AuthorID"`
	CreatedAt time.Time `json:"createdAt" gorm:"autoCreateTime"`
}
type Post struct {
	ID        int       `json:"id" gorm:"primaryKey;autoIncrement"`
	Author    User      `json:"author" gorm:"foreignKey:AuthorID;references:ID"`
	AuthorID  int       `json:"authorID"`
	Title     string    `json:"title" gorm:"not null"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"createdAt" gorm:"autoCreateTime"`
}
type UserBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
type PostBody struct {
	Title   string `json:"title" binding:"required"`
	Content string `json:"content" binding:"required"`
}

var store = sessions.NewCookieStore([]byte("secret"))

func main() {
	r := gin.Default()

	db := connectToDb()

	err := db.AutoMigrate(&User{}, &Post{})
	if err != nil {
		return
	}

	r.POST("/api/signup", func(c *gin.Context) {
		var body UserBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			return
		}

		var userCheck User

		result := db.Where("username = ?", body.Username).First(&userCheck)
		if result.RowsAffected != 0 {
			c.JSON(400, gin.H{
				"error": "User already exists",
			})
			return
		}

		hashedPass := hashPass(body.Password)

		user := User{
			Username: body.Username,
			Password: string(hashedPass),
		}

		db.Create(&user)

		session, _ := store.Get(c.Request, "session")
		session.Values["username"] = body.Username
		session.Values["id"] = user.ID

		err := session.Save(c.Request, c.Writer)
		if err != nil {
			return
		}

		c.JSON(200, gin.H{
			"message": "User created successfully",
		})
	})
	r.POST("/api/login", func(c *gin.Context) {
		var body UserBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			return
		}

		var user User

		result := db.Where("username = ?", body.Username).First(&user)

		if result.RowsAffected == 0 {
			c.JSON(404, gin.H{
				"error": "User not found",
			})
			c.Abort()
			return
		}

		if !comparePassword(user.Password, body.Password) {
			c.JSON(401, gin.H{
				"error": "Invalid password",
			})
			c.Abort()
			return
		}

		session, _ := store.Get(c.Request, "session")
		session.Values["username"] = body.Username
		session.Values["id"] = user.ID

		err := session.Save(c.Request, c.Writer)
		if err != nil {
			return
		}

		c.JSON(200, gin.H{
			"message": "User logged in successfully",
		})
	})
	r.GET("/api/posts", func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")

		if session.Values["id"] == nil {
			c.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}

		fmt.Println(session.Values["id"])

		id := session.Values["id"].(int)

		var posts []Post

		result := db.Where("authorID!=?", id).Preload("Author").Find(&posts)

		if result.RowsAffected == 0 {
			c.JSON(404, gin.H{
				"error": "No posts found",
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"posts": posts,
		})
	})
	r.POST("/api/posts", func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")

		if session.Values["id"] == nil {
			c.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}

		var body PostBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		var post Post

		post = Post{
			AuthorID: session.Values["id"].(int),
			Title:    body.Title,
			Content:  body.Content,
		}

		db.Create(&post)

		c.JSON(200, gin.H{
			"message": "Post created successfully",
		})
	})
	r.GET("/api/posts/user", func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")

		if session.Values["id"] == nil {
			c.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}

		var posts []Post

		result := db.Preload("Author").Where("id=?", session.Values["id"]).Find(&posts)

		if result.RowsAffected == 0 {
			c.JSON(404, gin.H{
				"error": "No posts found",
			})
			c.Abort()
			return
		}

		c.JSON(200, gin.H{
			"posts": posts,
		})
	})
}
