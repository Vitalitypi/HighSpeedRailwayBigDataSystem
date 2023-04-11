package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func RunHttpServer_Test() {
	// 1.创建路由
	r := gin.Default()
	// 2.绑定路由规则，执行的函数
	// gin.Context，封装了request和response
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello World!")
	})
	r.POST("/register", func(c *gin.Context) {
		fmt.Println(c.PostForm("name"))
		c.JSON(http.StatusOK, gin.H{
			"status": gin.H{
				"code":    http.StatusOK,
				"success": true,
			},
			"name": "Jane",
			"nick": "123",
		})
	})
	// 3.监听端口，默认在8080
	// Run("里面不指定端口号默认为8080")
	r.Run(":8000")
}
