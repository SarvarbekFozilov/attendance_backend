package hashing

import (
	"attendance/backend/foundation/web"
	submodel "attendance/backend/internal/repository/postgres/sub_model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/xuri/excelize/v2"
	"golang.org/x/text/unicode/norm"
)

type ExcelData struct {
	Data struct {
		Keys   any `json:"keys"`
		Values any `json:"values"`
	} `json:"data"`
	BasePath  string `json:"base_path"`
	FileName  string `json:"file_name"`
	ExcelPath string `json:"excel_path"`
}

type response struct {
	Message string `json:"message"`
	Status  bool   `json:"status"`
	Data    *struct {
		Excel string `json:"excel"`
	} `json:"data"`
}

func ExcelDog(data ExcelData) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "http://localhost:8022/generate-excel", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	resByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	res := response{}
	err = json.Unmarshal(resByte, &res)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 || res.Data == nil {
		return "", errors.New(fmt.Sprintf("status code: %d and message: %s", resp.StatusCode, res.Message))
	}

	return res.Data.Excel, nil
}

type UserExcellData struct {
	EmployeeID     string
	LastName       string
	FirstName      string
	NickName       string
	Role           string
	Password       string
	DepartmentName string
	DepartmentID   int
	PositionName   string
	PositionID     int
	Phone          string
	Email          string
	Error          string
}

func ExcelReaderByCreate(
	filePath string,
	fields map[int]string,
	departmentMap, positionMap map[string]int,
	employeeIDMap, existingEmailMap map[string]struct{},
) ([]UserExcellData, []submodel.InvalidUserResponse, error) {

	sheetName := "従業員"
	f, err := excelize.OpenFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, nil, err
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex := regexp.MustCompile(`^\+?\d+$`)

	var users []UserExcellData
	var invalidUsers []submodel.InvalidUserResponse

	localEmployeeIDs := make(map[string]int)
	localEmails := make(map[string]int)

	for i, row := range rows {
		if i == 0 {
			continue
		}

		get := func(idx int) string {
			if idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}

		userData := UserExcellData{
			EmployeeID:     get(0),
			LastName:       get(1),
			FirstName:      get(2),
			NickName:       get(3),
			Role:           get(4),
			Password:       get(5),
			Phone:          get(8),
			Email:          get(9),
			DepartmentName: get(6),
			PositionName:   get(7),
		}
		var userErrors submodel.UserErrors

		userRow := submodel.UserRow{
			EmployeeID:     userData.EmployeeID,
			LastName:       userData.LastName,
			FirstName:      userData.FirstName,
			NickName:       userData.NickName,
			Role:           userData.Role,
			Password:       userData.Password,
			DepartmentName: userData.DepartmentName,
			PositionName:   userData.PositionName,
			Phone:          userData.Phone,
			Email:          userData.Email,
		}

		// Validate required fields
		if userData.EmployeeID == "" {
			userErrors.EmployeeID = "Employee ID maydoni to'liq emas"
		}
		if userData.LastName == "" {
			userErrors.LastName = "Last Name maydoni to'liq emas"
		}
		if userData.FirstName == "" {
			userErrors.FirstName = "First Name maydoni to'liq emas"
		}
		if userData.Role == "" {
			userErrors.Role = "Role maydoni to'liq emas"
		}
		if userData.DepartmentName == "" {
			userErrors.DepartmentName = "Department maydoni to'liq emas"
		}
		if userData.PositionName == "" {
			userErrors.PositionName = "Position maydoni to'liq emas"
		}

		// Validate half-width characters
		if !isHalfWidth(userData.EmployeeID) {
			userErrors.EmployeeID = "EmployeeID Half-width formatda bo'lishi kerak"
		}
		if !isHalfWidth(userData.Password) {
			userErrors.Password = "Password Half-width formatda bo'lishi kerak"
		}
		if userData.Email != "" && !isHalfWidth(userData.Email) {
			userErrors.Email = "Email Half-width formatda bo'lishi kerak"
		}

		// Check for duplicates
		if _, exists := employeeIDMap[userData.EmployeeID]; exists {
			userErrors.EmployeeID = "Bu EmployeeID allaqachon mavjud (DBda)"
		}
		if prevRow, exists := localEmployeeIDs[userData.EmployeeID]; exists {
			userErrors.EmployeeID = fmt.Sprintf("Bu EmployeeID faylda dublikat (%d-qator)", prevRow)
		}

		// Validate email
		if userData.Email != "" {
			if _, exists := existingEmailMap[userData.Email]; exists {
				userErrors.Email = "Bu Email allaqachon mavjud (DBda)"
			}
			if prevRow, exists := localEmails[userData.Email]; exists {
				userErrors.Email = fmt.Sprintf("Bu Email faylda dublikat (%d-qator)", prevRow)
			}

			if !emailRegex.MatchString(userData.Email) {
				userErrors.Email = "Email formati noto'g'ri"
			}
		}

		// Validate phone
		if userData.Phone != "" && !phoneRegex.MatchString(userData.Phone) {
			userErrors.Phone = "Telefon raqam formati noto'g'ri"
		}

		// Check department and position
		_, deptOK := departmentMap[userData.DepartmentName]
		_, posOK := positionMap[userData.PositionName]
		if !deptOK {
			userErrors.DepartmentName = "Department nomi mavjud emas"
		}
		if !posOK {
			userErrors.PositionName = "Position nomi mavjud emas"
		}

		// Check if there are any errors
		hasErrors := userErrors != submodel.UserErrors{}
		if hasErrors {
			invalidUsers = append(invalidUsers, submodel.InvalidUserResponse{
				Row:    userRow,
				Errors: userErrors,
			})
			continue
		}

		// If no errors, add to valid users
		userData.DepartmentID = departmentMap[userData.DepartmentName]
		userData.PositionID = positionMap[userData.PositionName]

		localEmployeeIDs[userData.EmployeeID] = i + 1
		if userData.Email != "" {
			localEmails[userData.Email] = i + 1
		}

		users = append(users, userData)
	}

	return users, invalidUsers, nil
}
func ExcelReaderByEdit(
	filePath string,
	fields map[int]string,
	departmentMap, positionMap map[string]int,
	existingIDs, existingEmails map[string]struct{},
) ([]UserExcellData, []submodel.InvalidUserResponse, error) {

	sheetName := "従業員"
	f, err := excelize.OpenFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, nil, err
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex := regexp.MustCompile(`^\+?\d+$`)

	var users []UserExcellData
	var invalidUsers []submodel.InvalidUserResponse

	// Collect all IDs and Emails from the Excel file first
	localExistingIDs := make(map[string]struct{})
	localExistingEmails := make(map[string]struct{})
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) > 0 {
			id := strings.TrimSpace(row[0])
			if id != "" {
				localExistingIDs[id] = struct{}{}
			}
		}
		if len(row) > 9 {
			email := strings.TrimSpace(row[9])
			if email != "" {
				localExistingEmails[email] = struct{}{}
			}
		}
	}

	localIDs := make(map[string]int)
	localEmails := make(map[string]int)

	for i, row := range rows {
		if i == 0 {
			continue
		}

		get := func(idx int) string {
			if idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}

		userData := UserExcellData{
			EmployeeID:     get(0),
			LastName:       get(1),
			FirstName:      get(2),
			NickName:       get(3),
			Role:           get(4),
			Password:       get(5),
			DepartmentName: get(6),
			PositionName:   get(7),
			Phone:          get(8),
			Email:          get(9),
		}

		userRow := submodel.UserRow{
			EmployeeID:     userData.EmployeeID,
			LastName:       userData.LastName,
			FirstName:      userData.FirstName,
			NickName:       userData.NickName,
			Role:           userData.Role,
			Password:       userData.Password,
			DepartmentName: userData.DepartmentName,
			PositionName:   userData.PositionName,
			Phone:          userData.Phone,
			Email:          userData.Email,
		}

		var userErrors submodel.UserErrors

		// Validate required fields
		if userData.EmployeeID == "" {
			userErrors.EmployeeID = "Employee ID maydoni to'liq emas"
		}
		if userData.LastName == "" {
			userErrors.LastName = "Last Name maydoni to'liq emas"
		}
		if userData.FirstName == "" {
			userErrors.FirstName = "First Name maydoni to'liq emas"
		}
		if userData.Role == "" {
			userErrors.Role = "Role maydoni to'liq emas"
		}
		if userData.DepartmentName == "" {
			userErrors.DepartmentName = "Department maydoni to'liq emas"
		}
		if userData.PositionName == "" {
			userErrors.PositionName = "Position maydoni to'liq emas"
		}

		// Validate half-width characters
		if !isHalfWidth(userData.EmployeeID) {
			userErrors.EmployeeID = "EmployeeID Half-width formatda bo'lishi kerak"
		}
		if !isHalfWidth(userData.Password) {
			userErrors.Password = "Password Half-width formatda bo'lishi kerak"
		}
		if userData.Email != "" && !isHalfWidth(userData.Email) {
			userErrors.Email = "Email Half-width formatda bo'lishi kerak"
		}

		// Check department and position
		_, deptOK := departmentMap[userData.DepartmentName]
		_, posOK := positionMap[userData.PositionName]
		if !deptOK {
			userErrors.DepartmentName = "Department nomi mavjud emas"
		}
		if !posOK {
			userErrors.PositionName = "Position nomi mavjud emas"
		}

		// Check for duplicates in DB (excluding self)
		if _, exists := existingIDs[userData.EmployeeID]; exists {
			if _, selfExists := localExistingIDs[userData.EmployeeID]; !selfExists {
				userErrors.EmployeeID = "Bu EmployeeID allaqachon mavjud (DBda)"
			}
		}

		// Check for email duplicates in DB (excluding self)
		if userData.Email != "" {
			if _, exists := existingEmails[userData.Email]; exists {
				if _, selfExists := localExistingEmails[userData.Email]; !selfExists {
					userErrors.Email = "Bu Email allaqachon mavjud (DBda)"
				}
			}
		}

		// Validate email format
		if userData.Email != "" && !emailRegex.MatchString(userData.Email) {
			userErrors.Email = "Email formati noto'g'ri"
		}

		// Validate phone format
		if userData.Phone != "" && !phoneRegex.MatchString(userData.Phone) {
			userErrors.Phone = "Telefon raqam formati noto'g'ri"
		}

		// Check for duplicates within the file
		if prevRow, exists := localIDs[userData.EmployeeID]; exists {
			userErrors.EmployeeID = fmt.Sprintf("Bu Employee ID faylda dublikat (%d-qator)", prevRow)
		}
		if userData.Email != "" {
			if prevRow, exists := localEmails[userData.Email]; exists {
				userErrors.Email = fmt.Sprintf("Bu Email faylda dublikat (%d-qator)", prevRow)
			}
		}

		// Check if there are any errors
		hasErrors := userErrors != submodel.UserErrors{}
		if hasErrors {
			invalidUsers = append(invalidUsers, submodel.InvalidUserResponse{
				Row:    userRow,
				Errors: userErrors,
			})
			continue
		}

		// If no errors, add to valid users
		userData.DepartmentID = departmentMap[userData.DepartmentName]
		userData.PositionID = positionMap[userData.PositionName]

		localIDs[userData.EmployeeID] = i + 1
		if userData.Email != "" {
			localEmails[userData.Email] = i + 1
		}

		users = append(users, userData)
	}

	return users, invalidUsers, nil
}

func ExcelReaderByDelete(filePath string, rowLen int, fields map[int]string) ([]string, string, error) {
	sheetName := "従業員"
	f, err := excelize.OpenFile(filePath)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, "", err
	}

	var employeeIDs []string
	for i, row := range rows {
		if i == 0 {
			// Skip the header row
			continue
		}

		// Collect only EmployeeID (column 0 in your data)
		if len(row) > 0 && row[0] != "" {
			employeeIDs = append(employeeIDs, row[0])
		}
	}
	return employeeIDs, "", nil
}

// isHalfWidth checks if a string contains only half-width characters.
func isHalfWidth(s string) bool {
	// Normalize the string to NFC form.
	normalized := norm.NFC.String(s)
	for _, r := range normalized {
		// Full-width character detection
		if r >= '\uFF01' && r <= '\uFF60' || r >= '\uFFE0' && r <= '\uFFEF' {
			return false
		}
	}
	return true
}

func ValidateHalfWidthInput() web.Middleware {
	return func(handler web.Handler) web.Handler {
		return func(c *web.Context) error {
			// Iterate over form values and validate each one.
			for _, values := range c.Request.Form {
				for _, value := range values {
					if !isHalfWidth(value) {
						return c.RespondError(web.NewRequestError(
							errors.New("入力は半角文字のみ使用可能"), http.StatusBadRequest))
					}
				}
			}

			// Proceed to the next handler if validation passes.
			return handler(c)
		}
	}
}

func EditExcell(departments, positions []string) (string, error) {
	// Open the Excel file
	f, err := excelize.OpenFile("template.xlsx")
	if err != nil {
		return "", fmt.Errorf("failed to open Excel file: %w", err)
	}
	defer f.Close()

	department := "部署"
	position := "役職"

	// Check if the sheet exists
	if sheetIndex, err := f.GetSheetIndex(department); sheetIndex == -1 {
		if err != nil {
			return "", fmt.Errorf("failed to Department GetSheet  Excel file: %w", err)
		}
	}
	if sheetIndex, err := f.GetSheetIndex(position); sheetIndex == -1 {
		if err != nil {
			return "", fmt.Errorf("failed to Position GetSheet Excel file: %w", err)
		}
	}

	for i, dept := range departments {
		cell := fmt.Sprintf("A%d", i+2)
		if err := f.SetCellValue(department, cell, dept); err != nil {
			return "", fmt.Errorf("failed to write department data: %w", err)
		}
	}

	for i, pos := range positions {
		cell := fmt.Sprintf("A%d", i+2)
		if err := f.SetCellValue(position, cell, pos); err != nil {
			return "", fmt.Errorf("failed to write position data: %w", err)
		}
	}

	if err := f.Save(); err != nil {
		return "", fmt.Errorf("error saving file: %w", err)
	}
	return "template.xlsx", nil
}

func SaveInvalidUsersToExcel(employees []UserExcellData) (string, error) {
	templateFileName := "invalid_employees.xlsx"

	var f *excelize.File

	// Check if file exists
	if _, err := os.Stat(templateFileName); os.IsNotExist(err) {
		// Create a new file if the template doesn't exist
		f = excelize.NewFile()
		f.NewSheet("従業員")
	} else {
		// Open the existing template file
		f, err = excelize.OpenFile(templateFileName)
		if err != nil {
			return "", fmt.Errorf("failed to open template file: %w", err)
		}
	}
	defer f.Close()

	// Write Employee Data to the "Employees" sheet
	employeeSheet := "従業員"
	f.SetSheetName("Sheet1", employeeSheet)
	headers := []string{"社員番号", "姓", "名", "表示名", "権限", "パスワード", "部署", "役職", "電話番号", "メールアドレス", "エラー"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		if err := f.SetCellValue(employeeSheet, cell, header); err != nil {
			return "", fmt.Errorf("failed to write header in Employees sheet: %w", err)
		}
	}

	for i, emp := range employees {
		row := i + 2 // Start from the second row
		values := []interface{}{emp.EmployeeID, emp.LastName, emp.FirstName, emp.NickName, emp.Role, emp.Password, emp.DepartmentName, emp.PositionName, emp.Phone, emp.Email, emp.Error}
		for j, value := range values {
			cell := fmt.Sprintf("%c%d", 'A'+j, row)
			if err := f.SetCellValue(employeeSheet, cell, value); err != nil {
				return "", fmt.Errorf("failed to write employee data: %w", err)
			}
		}
	}

	// Save the file
	if err := f.SaveAs(templateFileName); err != nil {
		return "", fmt.Errorf("failed to save the Excel file: %w", err)
	}

	return "invalid_employees.xlsx", nil

}
