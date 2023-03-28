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
	"github.com/rs/xid"
)

type FileMetadata struct {
	ID         string    `json:"id"`          // file md5 checksum
	Name       string    `json:"name"`        // file name
	Size       int64     `json:"size"`        // file size
	Type       string    `json:"type"`        // file type
	Suffix     string    `json:"suffix"`      // file suffix
	UploadTime time.Time `json:"upload_time"` // upload time
}

const (
	FilesDir  = "./files"
	FilesJSON = "./files.json"
)

var (
	downloadToken = ""
	uploadToken   = ""
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
	fmt.Println("Note: Please use the following key to generate a TOTP token:")
	fmt.Println(key.Secret())

	downloadToken = xid.New().String()
	uploadToken = xid.New().String()

	// download token refresh every 1 hour
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			downloadToken = xid.New().String()
			uploadToken = xid.New().String()
		}
	}()

	// remove expired sessions every 1 hour
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			sm := session.GetInstance()
			sm.RemoveExpiredSessions()
		}
	}()

	// remove expired files every 1 hour
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			removeExpiredFiles()
		}
	}()

	r := gin.Default()
	r.Use(customRecovery())

	r.GET("/", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, loginHTML)
	})

	r.GET("/login", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, loginHTML)
	})

	r.GET("/files", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, filesHTML)
	})

	r.GET("/files/:id", func(ctx *gin.Context) {
		token := ctx.Query("token")
		if token != downloadToken {
			panic("Invalid token")
		}

		id := ctx.Param("id")

		metadata, err := readFilesMetadata()
		if err != nil {
			panic("Reading file metadata failed")
		}

		file, err := findFileByID(metadata, id)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		filePath := filepath.Join(FilesDir, file.ID+file.Suffix)
		ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.Name))
		ctx.Header("Content-Type", "application/octet-stream")
		ctx.Header("Content-Transfer-Encoding", "binary")
		ctx.File(filePath)
	})

	r.POST("/files/:fileToken", func(ctx *gin.Context) {
		if ctx.Param("fileToken") != uploadToken {
			panic("Invalid file token")
		}

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

		metadata, err := readFilesMetadata()
		if err != nil {
			panic("Reading file metadata failed")
		}

		for _, item := range metadata {
			if md5Str == item.ID {
				ctx.AbortWithStatusJSON(http.StatusConflict, gin.H{
					"message": "File already exists",
				})
				return
			}
		}

		content.Seek(0, 0)
		dst := filepath.Join(FilesDir, md5Str+filepath.Ext(file.Filename))

		if err := ctx.SaveUploadedFile(file, dst); err != nil {
			panic("Failed to save file")
		}

		if _, err := os.Stat(FilesDir); os.IsNotExist(err) {
			err = os.Mkdir(FilesDir, 0755)
			if err != nil {
				panic("Creating storage directory failed")
			}
		}

		fileData := FileMetadata{
			ID:         md5Str,
			Name:       file.Filename,
			Size:       file.Size,
			Type:       file.Header.Get("Content-Type"),
			Suffix:     filepath.Ext(file.Filename),
			UploadTime: time.Now(),
		}

		metadata = append(metadata, fileData)

		updatedFilesJSON, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			panic("Serializing updated file metadata failed")
		}

		err = ioutil.WriteFile(FilesJSON, updatedFilesJSON, 0644)
		if err != nil {
			panic("Writing updated file metadata to files.json failed")
		}

		ctx.JSON(200, fileData)
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
		metadata, _ := readFilesMetadata()

		ctx.JSON(http.StatusOK, gin.H{
			"data":          metadata,
			"downloadToken": downloadToken,
			"uploadToken":   uploadToken,
		})
	})

	api.DELETE("/files/:id", tokenHandler, func(ctx *gin.Context) {
		id := ctx.Param("id")

		data, err := ioutil.ReadFile(FilesJSON)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "Unable to read file metadata",
			})
			return
		}

		metadata, err := readFilesMetadata()
		if err != nil {
			panic("Reading file metadata failed")
		}

		var fileToDelete FileMetadata
		indexToDelete := -1
		for i, item := range metadata {
			if item.ID == id {
				fileToDelete = item
				indexToDelete = i
				break
			}
		}

		if indexToDelete == -1 {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "File not found",
			})
			return
		}

		err = os.Remove(filepath.Join(FilesDir, fileToDelete.ID+fileToDelete.Suffix))
		if err != nil {
			panic("Unable to delete file")
		}

		metadata = append(metadata[:indexToDelete], metadata[indexToDelete+1:]...)

		data, err = json.Marshal(metadata)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "Unable to marshal updated file metadata",
			})
			return
		}

		err = ioutil.WriteFile(FilesJSON, data, 0644)
		if err != nil {
			fmt.Println(err)
			panic("Unable to write updated file metadata to files.json")
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": "File deleted successfully",
		})
	})

	r.Run(":8086")
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

func readFilesMetadata() ([]FileMetadata, error) {
	// checkout file if not exists create it
	if _, err := os.Stat(FilesJSON); os.IsNotExist(err) {
		_, err := os.Create(FilesJSON)
		if err != nil {
			return nil, err
		}
	}
	data, err := ioutil.ReadFile(FilesJSON)
	if err != nil {
		return nil, err
	}

	metadata := []FileMetadata{}
	if len(data) == 0 {
		return metadata, nil
	}

	err = json.Unmarshal(data, &metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func findFileByID(metadata []FileMetadata, id string) (*FileMetadata, error) {
	for _, file := range metadata {
		if file.ID == id {
			return &file, nil
		}
	}

	return nil, fmt.Errorf("file with ID %s not found", id)
}

func removeExpiredFiles() {
	metadata, err := readFilesMetadata()
	if err == nil {
		panic("Reading file metadata failed")
	}

	md := []FileMetadata{}

	for _, file := range metadata {
		if time.Now().After(file.UploadTime.Add(24 * time.Hour)) {
			err := os.Remove(filepath.Join(FilesDir, file.ID+file.Suffix))
			if err != nil {
				panic("Unable to delete file")
			}
			md = append(md, file)
		}
	}

	data, err := json.Marshal(md)
	if err == nil {
		ioutil.WriteFile(FilesJSON, data, 0644)
	}
}
