package main

import (
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pengist/filehub/session"
	"github.com/pquerna/otp/totp"
)

type FileMetadata struct {
	ID         string    `json:"id"`          // file md5 checksum
	Name       string    `json:"name"`        // file name
	Size       int64     `json:"size"`        // file size
	UploadTime time.Time `json:"upload_time"` // upload time
}

const (
	FilesDir  = "./files"
	FilesJSON = "./files.json"
)

//go:embed login.html
var loginHTML string

//go:embed files.html
var filesHTML string

var key, _ = totp.Generate(totp.GenerateOpts{
	Issuer:      "FileHub",
	AccountName: "admin",
})

func main() {
	fmt.Println("key:", key.Secret())
	fmt.Println(key)

	r := gin.Default()
	r.Use(customRecovery())

	r.GET("/login", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, loginHTML)
	})

	r.GET("/files", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, filesHTML)
	})

	api := r.Group("/api")

	api.POST("/login", func(ctx *gin.Context) {
		code := ctx.PostForm("code")
		if code == "" {
			panic("Code is required")
		}

		valid := totp.Validate(code, key.Secret())
		if !valid {
			panic("Invalid code")
		}

		sm := session.GetInstance()
		session := sm.CreateSession(1 * time.Hour)

		ctx.JSON(http.StatusOK, gin.H{"message": "Logged in", "token": session.Token})
	})

	api.POST("/logout", tokenHandler, func(ctx *gin.Context) {
		token := ctx.GetHeader("token")

		sm := session.GetInstance()
		sm.RemoveSession(token)

		ctx.JSON(200, gin.H{"message": "Logged out successfully"})
	})

	api.GET("/files", tokenHandler, func(ctx *gin.Context) {
		var metadata []FileMetadata
		filesJSON, err := ioutil.ReadFile(FilesJSON)
		if err == nil {
			err = json.Unmarshal(filesJSON, &metadata)
			if err != nil {
				panic("Reading existing file metadata failed")
			}
		}
		ctx.JSON(http.StatusOK, metadata)
	})

	api.GET("/files/:id", tokenHandler, func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"file": FileMetadata{}})
	})

	api.POST("/files", tokenHandler, func(ctx *gin.Context) {
		file, err := ctx.FormFile("file")
		if err != nil {
			panic("File upload failed")
		}

		content, _ := file.Open()
		hash := md5.New()
		if _, err := io.Copy(hash, content); err != nil {
			panic("Failed to calculate MD5")
		}
		hashInBytes := hash.Sum(nil)[:16]
		md5Str := hex.EncodeToString(hashInBytes)

		content.Seek(0, 0)
		dst := filepath.Join(FilesDir, md5Str)
		if err := ctx.SaveUploadedFile(file, dst); err != nil {
			panic("Failed to save file")
		}

		if _, err := os.Stat(FilesDir); os.IsNotExist(err) {
			err = os.Mkdir(FilesDir, 0755)
			if err != nil {
				panic("Creating storage directory failed")
			}
		}

		fileMetadata := FileMetadata{
			ID:         md5Str,
			Name:       file.Filename,
			Size:       file.Size,
			UploadTime: time.Now(),
		}

		var existingMetadata []FileMetadata
		filesJSON, err := ioutil.ReadFile(FilesJSON)
		if err == nil {
			err = json.Unmarshal(filesJSON, &existingMetadata)
			if err != nil {
				panic("Reading existing file metadata failed")
			}
		}

		existingMetadata = append(existingMetadata, fileMetadata)

		updatedFilesJSON, err := json.MarshalIndent(existingMetadata, "", "  ")
		if err != nil {
			panic("Serializing updated file metadata failed")
		}

		err = ioutil.WriteFile(FilesJSON, updatedFilesJSON, 0644)
		if err != nil {
			panic("Writing updated file metadata to files.json failed")
		}

		ctx.JSON(200, fileMetadata)
	})

	r.Run(":8080")
}

func customRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("Panic occurred: %v\n", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": err})
				c.Abort()
			}
		}()

		c.Next()
	}
}

func tokenHandler(ctx *gin.Context) {
	token := ctx.GetHeader("token")
	if token == "" {
		panic("Unauthorized")
	}

	sm := session.GetInstance()
	session, ok := sm.GetSession(token)
	if !ok {
		panic("Unauthorized")
	}

	if time.Now().After(session.ExpiresAt) {
		panic("Unauthorized")
	}
}
