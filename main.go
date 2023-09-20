package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var users []User

func main() {
	router := gin.Default()

	// 登录路由处理程序
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	router.GET("/error1", func(c *gin.Context) {
		c.HTML(http.StatusOK, "error1.html", gin.H{})
	})

	router.GET("/error2", func(c *gin.Context) {
		c.HTML(http.StatusOK, "error2.html", gin.H{})
	})

	router.POST("/login", func(c *gin.Context) {
		var user User

		// 解析请求体中的JSON数据
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 查找用户
		var foundUser *User
		for i, u := range users {
			if u.Email == user.Email {
				foundUser = &users[i]
				break
			}
		}
		print(foundUser)
		print(foundUser == nil)
		// 检查用户是否存在
		if foundUser == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
			return
		}

		// 生成带盐的MD5哈希值
		salt := "SALT"
		hasher := md5.New()
		hasher.Write([]byte(user.Password + salt))
		inputPasswordHash := hex.EncodeToString(hasher.Sum(nil))

		// 检查密码是否匹配
		if foundUser.Password != inputPasswordHash {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "登录成功"})
	})

	// 注册路由处理程序
	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{})
	})

	router.POST("/register", func(c *gin.Context) {
		var user User

		// 解析请求体中的JSON数据
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 检查用户是否已经存在
		for _, u := range users {
			if u.Email == user.Email {
				print("error2")
				//重定向到error2
				c.JSON(http.StatusUnauthorized, gin.H{"error": "用户已经存在"})
				return
			}
		}

		// 生成带盐的MD5哈希值
		salt := "SALT"
		hasher := md5.New()
		hasher.Write([]byte(user.Password + salt))
		passwordHash := hex.EncodeToString(hasher.Sum(nil))

		// 将用户添加到用户列表中
		user.Password = passwordHash
		users = append(users, user)

		c.JSON(http.StatusOK, gin.H{"status": "注册成功"})

		// 重定向到登录页面
		c.Redirect(http.StatusFound, "/login")
	})

	// 静态文件服务
	router.Static("/static", "./static")
	router.LoadHTMLFiles("login.html", "register.html")
	// 启动HTTP服务器
	router.Run(":8082")
}
