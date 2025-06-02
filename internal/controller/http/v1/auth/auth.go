package auth

import (
	"attendance/backend/foundation/web"
	"attendance/backend/internal/commands"
	"attendance/backend/internal/entity"
	"attendance/backend/internal/repository/postgres/user"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	errIncorrectPassword   = errors.New("社員番号またはメールアドレスが間違っています")
	errIncorrectEmployeeId = errors.New("パスワードが間違っています")
	googleOAuthConfig      *oauth2.Config
	frontendURL            string
)

type Controller struct {
	user User
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

func NewController(user User) *Controller {
	return &Controller{user: user}
}

func InitGoogleProvider(clientID, clientSecret, redirectURL, frontendURLConfig string) {
    fmt.Println("=== DEBUG: InitGoogleProvider called ===")
    fmt.Printf("ClientID: '%s'\n", clientID)
    fmt.Printf("ClientSecret: '%s'\n", clientSecret)

	googleOAuthConfig = &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	frontendURL = frontendURLConfig
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper function to check if a string is a valid email
func isValidEmail(email string) bool {
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}

// @Description SignIn User
// @Summary SignIn User
// @Tags Auth
// @Accept json
// @Produce json
// @Param login body user.SignInRequest true "Sign In"
// @Success 200 {object} web.ErrorResponse
// @Failure 400,404,500,401 {object} web.ErrorResponse
// @Router /api/v1/sign-in [post]
func (uc Controller) SignIn(c *web.Context) error {
	var data user.SignInRequest
	err := c.BindFunc(&data, "EmployeeID", "Password")
	if err != nil {
		fmt.Println("Error binding request data:", err)
		return c.RespondError(&web.Error{
			Err:    errors.New("invalid request data"),
			Status: http.StatusBadRequest,
		})
	}

	var detail *entity.User
	if isValidEmail(data.EmployeeID) {
		// Fetch user by Email
		detail, err = uc.user.GetByEmployeeEmail(c.Ctx, data.EmployeeID)
	} else {
		// Fetch user by EmployeeID
		detail, err = uc.user.GetByEmployeeID(c.Ctx, data.EmployeeID)
	}

	if err != nil || detail == nil {
		fmt.Println("User not found or invalid credentials for Identifier:", data.EmployeeID)
		return c.RespondError(&web.Error{
			Err:    errIncorrectPassword,
			Status: http.StatusUnauthorized,
		})
	}

	if detail.Password == nil {
		fmt.Println("Password not found for Identifier:", data.EmployeeID)
		return c.RespondError(&web.Error{
			Err:    errIncorrectEmployeeId,
			Status: http.StatusNotFound,
		})
	}

	// Verify password
	if err = bcrypt.CompareHashAndPassword([]byte(*detail.Password), []byte(data.Password)); err != nil {
		fmt.Println("Incorrect password for Identifier:", data.EmployeeID)
		return c.RespondError(&web.Error{
			Err:    errIncorrectEmployeeId,
			Status: http.StatusUnauthorized,
		})
	}

	// Generate tokens
	accessToken, refreshToken, err := commands.GenToken(user.AuthClaims{
		ID:   detail.ID,
		Role: *detail.Role,
	}, "./private.pem")

	if err != nil {
		fmt.Println("Error generating tokens:", err)
		return c.RespondError(&web.Error{
			Err:    errors.New("token generation failed"),
			Status: http.StatusInternalServerError,
		})
	}

	return c.Respond(map[string]interface{}{
		"status": true,
		"data": map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"role":          *detail.Role,
		},
		"error": nil,
	}, http.StatusOK)
}

// @Description Refresh Token
// @Summary Refresh Token
// @Tags Auth
// @Accept json
// @Produce json
// @Param refresh body user.RefreshTokenRequest true "Refresh Token"
// @Success 200 {object} web.ErrorResponse
// @Failure 400,404,500,401 {object} web.ErrorResponse
// @Router /api/v1/refresh-token [post]
func (uc Controller) RefreshToken(c *web.Context) error {
	var data user.RefreshTokenRequest

	err := c.BindFunc(&data, "AccessToken", "RefreshToken")
	if err != nil {
		return c.RespondError(err)
	}

	_, refreshTokenClaims, err := commands.VerifyTokens(data.AccessToken, data.RefreshToken, "./private.pem")
	if err != nil {
		return c.RespondError(web.NewRequestError(err, http.StatusUnauthorized))
	}

	// Generate new tokens
	userClaims := user.AuthClaims{
		ID:   refreshTokenClaims.UserId,
		Role: refreshTokenClaims.Role,
	}

	accessToken, refreshToken, err := commands.GenToken(userClaims, "./private.pem")
	if err != nil {
		return c.RespondError(web.NewRequestError(errors.Wrap(err, "generating new tokens"), http.StatusInternalServerError))
	}

	return c.Respond(map[string]interface{}{
		"status": true,
		"data": map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
		"error": nil,
	}, http.StatusOK)
}


func (uc Controller) GoogleAuth(c *web.Context) error {
    if googleOAuthConfig == nil {
        return c.RespondError(&web.Error{
            Err:    errors.New("Google OAuth not configured"),
            Status: http.StatusInternalServerError,
        })
    }

    state := generateRandomState()
    
    oauthURL := googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
    
    fmt.Printf("Redirecting to Google OAuth: %s\n", oauthURL)
	fmt.Printf("Redirecting to ClientID: %s\n", googleOAuthConfig.ClientID)
	fmt.Printf("Redirecting to ClientID: %s\n", googleOAuthConfig.ClientSecret)
    
    c.Redirect(http.StatusTemporaryRedirect, oauthURL)
    return nil
}

func (uc Controller) GoogleCallback(c *web.Context) error {
	if googleOAuthConfig == nil {
		return c.RespondError(&web.Error{
			Err:    errors.New("Google OAuth not configured"),
			Status: http.StatusInternalServerError,
		})
	}

	code := c.Query("code")
	if code == "" {
		errorParam := c.Query("error")
		if errorParam != "" {
			fmt.Printf("OAuth error: %s\n", errorParam)
			redirectURL := fmt.Sprintf("%s/login?error=%s", frontendURL, url.QueryEscape(errorParam))
			c.Redirect(http.StatusTemporaryRedirect, redirectURL)
			return nil
		}

		return c.RespondError(&web.Error{
			Err:    errors.New("authorization code not found"),
			Status: http.StatusBadRequest,
		})
	}

	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Token exchange error: %v\n", err)
		return c.RespondError(&web.Error{
			Err:    errors.Wrap(err, "failed to exchange token"),
			Status: http.StatusBadRequest,
		})
	}

	client := googleOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return c.RespondError(&web.Error{
			Err:    errors.Wrap(err, "failed to get user info"),
			Status: http.StatusInternalServerError,
		})
	}
	defer resp.Body.Close()

	var googleUser GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return c.RespondError(&web.Error{
			Err:    errors.Wrap(err, "failed to decode user info"),
			Status: http.StatusInternalServerError,
		})
	}

	fmt.Printf("Google user info: %+v\n", googleUser)
	detail, err := uc.user.GetByEmployeeEmail(c.Ctx, googleUser.Email)
	if err != nil || detail == nil {
		fmt.Printf("User not found for email: %s\n", googleUser.Email)
		errorMsg := "ユーザーが見つかりません。管理者にお問い合わせください。"
		redirectURL := fmt.Sprintf("%s/login?error=%s", frontendURL, url.QueryEscape(errorMsg))
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return nil
	}

	accessToken, refreshToken, err := commands.GenToken(user.AuthClaims{
		ID:   detail.ID,
		Role: *detail.Role,
	}, "./private.pem")

	if err != nil {
		fmt.Printf("Error generating tokens: %v\n", err)
		return c.RespondError(&web.Error{
			Err:    errors.New("token generation failed"),
			Status: http.StatusInternalServerError,
		})
	}

	redirectURL := fmt.Sprintf("%s/auth/callback?access_token=%s&refresh_token=%s&role=%s",
		frontendURL,
		url.QueryEscape(accessToken),
		url.QueryEscape(refreshToken),
		url.QueryEscape(*detail.Role))

	fmt.Printf("Redirecting to frontend: %s\n", redirectURL)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	return nil
}
