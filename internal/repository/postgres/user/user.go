package user

import (
	"context"
	"database/sql"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/jung-kurt/gofpdf/v2"

	"io"
	"io/ioutil"
	"net/http"

	"attendance/backend/foundation/web"
	"attendance/backend/internal/auth"
	"attendance/backend/internal/entity"
	"attendance/backend/internal/pkg/repository/postgresql"
	"attendance/backend/internal/repository/postgres"
	"attendance/backend/internal/repository/postgres/department"
	"attendance/backend/internal/repository/postgres/position"
	submodel "attendance/backend/internal/repository/postgres/sub_model"
	"attendance/backend/internal/service"
	"attendance/backend/internal/service/hashing"

	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

type Repository struct {
	*postgresql.Database
	PositionRepo   *position.Repository
	DepartmentRepo *department.Repository
}

func NewRepository(database *postgresql.Database) *Repository {
	return &Repository{Database: database}
}

func (r Repository) GetByEmployeeID(ctx context.Context, employee_id string) (*entity.User, error) {
	var detail entity.User
	err := r.NewSelect().Model(&detail).Where("employee_id = ? AND deleted_at IS NULL", employee_id).Scan(ctx)

	if err != nil {
		return &entity.User{}, &web.Error{
			Err:    errors.New("employee not found!"),
			Status: http.StatusUnauthorized,
		}
	}
	return &detail, err
}
func (r Repository) GetByEmployeeEmail(ctx context.Context, email string) (*entity.User, error) {
	var detail entity.User
	err := r.NewSelect().Model(&detail).Where("email = ? AND deleted_at IS NULL", email).Scan(ctx)

	if err != nil {
		return &entity.User{}, &web.Error{
			Err:    errors.New("employee not found!"),
			Status: http.StatusUnauthorized,
		}
	}
	return &detail, err
}

func (r Repository) GetFullName(ctx context.Context) (GetFullName, error) {
	claims, err := r.CheckClaims(ctx, auth.RoleEmployee)
	if err != nil {
		return GetFullName{}, err
	}

	query := fmt.Sprintf(`
		SELECT
		     CONCAT(first_name, ' ', last_name) AS full_name,
			 employee_id

		FROM
		    users
		WHERE deleted_at IS NULL AND role='EMPLOYEE' AND id = %d
	`, claims.UserId)

	var detail GetFullName

	err = r.QueryRowContext(ctx, query).Scan(
		&detail.FullName,
		&detail.EmployeeID,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return GetFullName{}, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
	}
	if err != nil {
		return GetFullName{}, web.NewRequestError(errors.Wrap(err, "selecting employee_name detail"), http.StatusBadRequest)
	}

	return detail, nil
}
func (r Repository) GetList(ctx context.Context, filter Filter) ([]GetListResponse, int, error) {
	_, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return nil, 0, err
	}

	whereQuery := fmt.Sprintf(`
			WHERE 
				u.deleted_at IS NULL and role='EMPLOYEE'
			`)

	if filter.Search != nil {
		search := strings.Replace(*filter.Search, " ", "", -1)
		search = strings.Replace(search, "'", "", -1)

		whereQuery += fmt.Sprintf(` AND
		u.employee_id ilike '%s' OR u.last_name ilike '%s'`, "%"+search+"%", "%"+search+"%")
	}
	if filter.DepartmentID != nil {
		whereQuery += fmt.Sprintf(` AND u.department_id = %d`, *filter.DepartmentID)
	}
	if filter.PositionID != nil {
		whereQuery += fmt.Sprintf(` AND u.position_id = %d`, *filter.PositionID)
	}
	orderQuery := "ORDER BY u.employee_id desc"

	var limitQuery, offsetQuery string

	if filter.Page != nil && filter.Limit != nil {
		offset := (*filter.Page - 1) * (*filter.Limit)
		filter.Offset = &offset
	}

	if filter.Limit != nil {
		limitQuery += fmt.Sprintf(" LIMIT %d", *filter.Limit)
	}

	if filter.Offset != nil {
		offsetQuery += fmt.Sprintf(" OFFSET %d", *filter.Offset)
	}

	query := fmt.Sprintf(`
		SELECT 
			u.id,
			u.employee_id,
			CONCAT(u.first_name, ' ', u.last_name) AS full_name,
			u.nick_name,
			u.department_id,
			d.name as department_name,
			u.position_id,
			p.name as position_name,
			u.phone,
			u.email
		FROM users u
		 JOIN department d ON d.id=u.department_id and d.deleted_at is null
		 JOIN position p ON p.id=u.position_id and p.deleted_at is null

		%s %s %s %s
	`, whereQuery, orderQuery, limitQuery, offsetQuery)

	rows, err := r.QueryContext(ctx, query)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
	}
	if err != nil {
		return nil, 0, web.NewRequestError(errors.Wrap(err, "selecting users"), http.StatusBadRequest)
	}

	var list []GetListResponse

	for rows.Next() {
		var detail GetListResponse
		var nickName sql.NullString
		if err = rows.Scan(
			&detail.ID,
			&detail.EmployeeID,
			&detail.FullName,
			&nickName,
			&detail.DepartmentID,
			&detail.Department,
			&detail.PositionID,
			&detail.Position,
			&detail.Phone,
			&detail.Email); err != nil {
			return nil, 0, web.NewRequestError(errors.Wrap(err, "scanning user list"), http.StatusBadRequest)
		}
		if nickName.Valid {
			detail.NickName = nickName.String
		} else {
			detail.NickName = ""
		}

		list = append(list, detail)
	}

	countQuery := fmt.Sprintf(`
		SELECT
			count(u.id)
		FROM  users u
		 JOIN department d ON d.id=u.department_id and d.deleted_at is null
		 JOIN position p ON p.id=u.position_id and p.deleted_at is null
			%s
	`, whereQuery)

	countRows, err := r.QueryContext(ctx, countQuery)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
	}
	if err != nil {
		return nil, 0, web.NewRequestError(errors.Wrap(err, "selecting users"), http.StatusBadRequest)
	}

	count := 0

	for countRows.Next() {
		if err = countRows.Scan(&count); err != nil {
			return nil, 0, web.NewRequestError(errors.Wrap(err, "scanning user count"), http.StatusBadRequest)
		}
	}
	return list, count, nil
}

func (r Repository) GetDetailById(ctx context.Context, id int) (GetDetailByIdResponse, error) {
	_, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return GetDetailByIdResponse{}, err
	}

	query := fmt.Sprintf(`
		SELECT
			u.id,
			u.employee_id,
			CONCAT(u.first_name, ' ', u.last_name) AS full_name,
			u.nick_name,
			u.department_id,
			d.name,
			u.position_id,
			p.name,
			u.phone,
			u.email
		FROM
		    users u 
		RIGHT JOIN department d ON u.department_id = d.id and d.deleted_at is null
		RIGHT JOIN  position p ON u.position_id=p.id and p.deleted_at is null
		WHERE u.deleted_at IS NULL and role = 'EMPLOYEE' AND u.id = %d
	`, id)

	var detail GetDetailByIdResponse
	var nickName sql.NullString

	err = r.QueryRowContext(ctx, query).Scan(
		&detail.ID,
		&detail.EmployeeID,
		&detail.FullName,
		&nickName,
		&detail.DepartmentID,
		&detail.Department,
		&detail.PositionID,
		&detail.Position,
		&detail.Phone,
		&detail.Email,
	)
	if nickName.Valid {
		detail.NickName = nickName.String
	} else {
		detail.NickName = ""
	}
	if errors.Is(err, sql.ErrNoRows) {
		return GetDetailByIdResponse{}, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
	}
	if err != nil {
		return GetDetailByIdResponse{}, web.NewRequestError(errors.Wrap(err, "selecting user detail"), http.StatusBadRequest)
	}

	return detail, nil
}
func (r Repository) Create(ctx context.Context, request CreateRequest) (CreateResponse, error) {
	claims, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return CreateResponse{}, err
	}

	// Trim spaces from user input fields
	*request.EmployeeID = strings.TrimSpace(*request.EmployeeID)
	*request.FirstName = strings.TrimSpace(*request.FirstName)
	*request.LastName = strings.TrimSpace(*request.LastName)
	*request.Password = strings.TrimSpace(*request.Password)
	*request.Email = strings.TrimSpace(*request.Email)

	// Check if any of the fields are empty
	if *request.EmployeeID == "" || *request.FirstName == "" || *request.LastName == "" || *request.Password == "" || *request.Email == "" {
		return CreateResponse{}, web.NewRequestError(errors.New("必須項目は空欄にできません、またはスペースのみを含むことはできません。"), http.StatusBadRequest)
	}

	// Validate struct for required fields
	if err := r.ValidateStruct(&request, "EmployeeID", "Password", "Role", "FirstName,LastName"); err != nil {
		return CreateResponse{}, err
	}

	// Check if the EmployeeID already exists
	EmployeeID := true
	if err := r.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT CASE WHEN 
							(SELECT employee_id FROM users WHERE employee_id = '%s' AND deleted_at IS NULL) IS NOT NULL 
							THEN true ELSE false END`, *request.EmployeeID)).Scan(&EmployeeID); err != nil {
		return CreateResponse{}, web.NewRequestError(errors.Wrap(err, "employee_id name check"), http.StatusInternalServerError)
	}

	if EmployeeID {
		return CreateResponse{}, web.NewRequestError(errors.New("社員番号はすでに使用されています。"), http.StatusBadRequest)
	}

	// Check if department exists
	var deptExists bool
	err = r.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM department WHERE id = ? AND deleted_at IS NULL)", request.DepartmentID).Scan(&deptExists)
	if err != nil || !deptExists {
		return CreateResponse{}, web.NewRequestError(errors.New("invalid department ID"), http.StatusBadRequest)
	}

	// Check if position exists
	var posExists bool
	err = r.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM position WHERE id = ? AND deleted_at IS NULL)", request.PositionID).Scan(&posExists)
	if err != nil || !posExists {
		return CreateResponse{}, web.NewRequestError(errors.New("invalid position ID"), http.StatusBadRequest)
	}

	// Check if the email already exists
	Email := true
	if err := r.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT CASE WHEN 
							(SELECT email FROM users WHERE email = '%s' AND deleted_at IS NULL) IS NOT NULL 
							THEN true ELSE false END`, *request.Email)).Scan(&Email); err != nil {
		return CreateResponse{}, web.NewRequestError(errors.Wrap(err, "email name check"), http.StatusInternalServerError)
	}

	if Email {
		return CreateResponse{}, web.NewRequestError(errors.New("メールアドレス はすでに使用されています。"), http.StatusBadRequest)
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(*request.Password), bcrypt.DefaultCost)
	if err != nil {
		return CreateResponse{}, web.NewRequestError(errors.Wrap(err, "hashing password"), http.StatusInternalServerError)
	}
	hashedPassword := string(hash)

	// Set user role
	var response CreateResponse
	role := strings.ToUpper(*request.Role)
	if (role != "EMPLOYEE") && (role != "ADMIN") {
		return CreateResponse{}, web.NewRequestError(errors.New("incorrect role. role should be EMPLOYEE or ADMIN"), http.StatusBadRequest)
	}
	response.Role = role
	response.FirstName = request.FirstName
	response.LastName = request.LastName
	response.NickName = request.NickName
	response.EmployeeID = request.EmployeeID
	response.DepartmentID = request.DepartmentID
	response.Password = &hashedPassword
	response.PositionID = request.PositionID
	response.Phone = request.Phone
	response.Email = request.Email
	response.CreatedAt = time.Now()
	response.CreatedBy = claims.UserId

	// Insert into database
	_, err = r.NewInsert().Model(&response).Returning("id").Exec(ctx, &response.ID)
	if err != nil {
		return CreateResponse{}, web.NewRequestError(errors.Wrap(err, "creating user"), http.StatusBadRequest)
	}

	// Clear the password before returning the response
	response.Password = nil

	return response, nil
}

func (r Repository) UpdateColumns(ctx context.Context, request UpdateRequest) error {
	claims, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return err
	}

	if err := r.ValidateStruct(&request, "ID"); err != nil {
		return err
	}

	// Check if any of the fields are empty
	if *request.EmployeeID == "" || *request.FirstName == "" || *request.LastName == "" || *request.Email == "" {
		return web.NewRequestError(errors.New("必須項目は空欄にできません、またはスペースのみを含むことはできません。"), http.StatusBadRequest)
	}

	q := r.NewUpdate().Table("users").Where("deleted_at IS NULL AND id = ? ", request.ID)

	if request.EmployeeID != nil {
		userIdStatus := true
		if err := r.QueryRowContext(ctx, fmt.Sprintf("SELECT CASE WHEN (SELECT id FROM users WHERE employee_id = '%s' AND deleted_at IS NULL AND id != %d) IS NOT NULL THEN true ELSE false END", *request.EmployeeID, request.ID)).Scan(&userIdStatus); err != nil {
			return web.NewRequestError(errors.Wrap(err, "employee_id check"), http.StatusInternalServerError)
		}
		if userIdStatus {
			return web.NewRequestError(errors.Wrap(errors.New(""), "社員番号はすでに使用されています。"), http.StatusBadRequest)
		}
		q.Set("employee_id = ?", request.EmployeeID)
	}

	if request.Email != nil {
		emailStatus := true
		if err := r.QueryRowContext(ctx, fmt.Sprintf("SELECT CASE WHEN (SELECT id FROM users WHERE email = '%s' AND deleted_at IS NULL AND id != %d) IS NOT NULL THEN true ELSE false END", *request.Email, request.ID)).Scan(&emailStatus); err != nil {
			return web.NewRequestError(errors.Wrap(err, "email check"), http.StatusInternalServerError)
		}
		if emailStatus {
			return web.NewRequestError(errors.Wrap(errors.New(""), "メールアドレス はすでに使用されています。"), http.StatusBadRequest)
		}
		q.Set("email = ?", request.Email)
	}
	var deptExists bool
	err = r.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM department WHERE id = ? AND deleted_at IS NULL)", request.DepartmentID).Scan(&deptExists)
	if err != nil || !deptExists {
		return web.NewRequestError(errors.New("invalid department ID"), http.StatusBadRequest)
	}

	var posExists bool
	err = r.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM position WHERE id = ? AND deleted_at IS NULL)", request.PositionID).Scan(&posExists)
	if err != nil || !posExists {
		return web.NewRequestError(errors.New("invalid position ID"), http.StatusBadRequest)
	}
	if request.Role != nil {
		role := strings.ToUpper(*request.Role)
		if (role != "EMPLOYEE") && (role != "ADMIN") {
			return web.NewRequestError(errors.New("incorrect role. role should be EMPLOYEE or ADMIN"), http.StatusBadRequest)
		}
		q.Set("role = ?", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return web.NewRequestError(errors.Wrap(err, "hashing password"), http.StatusInternalServerError)
	}
	hashedPassword := string(hash)

	if request.FirstName != nil {
		q.Set("first_name = ?", request.FirstName)
	}

	if request.LastName != nil {
		q.Set("last_name = ?", request.LastName)
	}
	if request.NickName != nil {
		q.Set("nick_name = ?", request.NickName)
	}
	if request.DepartmentID != nil {
		q.Set("department_id = ?", request.DepartmentID)
	}
	if request.PositionID != nil {
		q.Set("position_id=?", request.PositionID)
	}
	if request.Phone != nil {
		q.Set("phone=?", request.Phone)
	}
	if request.Password != "" {
		q.Set("password=?", hashedPassword)
	}

	q.Set("updated_at = ?", time.Now())
	q.Set("updated_by = ?", claims.UserId)

	_, err = q.Exec(ctx)
	if err != nil {
		return web.NewRequestError(errors.Wrap(err, "updating user"), http.StatusBadRequest)
	}

	return nil
}
func (r Repository) Delete(ctx context.Context, id int) error {
	return r.DeleteRow(ctx, "users", id)
}

func (r Repository) CreateByExcell(ctx context.Context, request ExcellRequest) (int, []submodel.InvalidUserResponse, error) {
	claims, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return 0, nil, err
	}
	if err := r.ValidateStruct(&request); err != nil {
		return 0, nil, err
	}
	departmentMap, err := r.LoadDepartmentMap(ctx)
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "loading department map"), http.StatusInternalServerError)
	}

	positionMap, err := r.LoadPositionMap(ctx)
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "loading position map"), http.StatusInternalServerError)
	}

	employeeIDMap := make(map[string]struct{})
	emailMap := make(map[string]struct{})

	rows, err := r.QueryContext(ctx,
		"SELECT employee_id, email FROM users WHERE role='EMPLOYEE' AND deleted_at IS NULL")
	if err != nil {
		return 0, nil, web.NewRequestError(
			errors.Wrap(err, "getting employee data"),
			http.StatusInternalServerError,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var employeeID, email string

		if err := rows.Scan(&employeeID, &email); err != nil {
			return 0, nil, web.NewRequestError(
				errors.Wrap(err, "scanning employee data"),
				http.StatusInternalServerError,
			)
		}

		// Employee ID ni mapga qo'shish
		employeeIDMap[employeeID] = struct{}{}

		// Email bo'sh bo'lmaganda mapga qo'shish
		if email != "" {
			emailMap[email] = struct{}{}
		}
	}

	// Iteratsiya xatolari uchun tekshirish
	if err := rows.Err(); err != nil {
		return 0, nil, web.NewRequestError(
			errors.Wrap(err, "database iteration error"),
			http.StatusInternalServerError,
		)
	}
	file, err := request.Excell.Open()
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "opening excel file"), http.StatusBadRequest)
	}
	defer file.Close()

	tempFile, err := ioutil.TempFile("", "excel-*.xlsx")
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "creating temporary file"), http.StatusInternalServerError)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "copying excel file"), http.StatusInternalServerError)
	}
	fields := map[int]string{
		0: "EmployeeID",
		1: "LastName",
		2: "Firstname",
		3: "NickName",
		4: "Role",
		5: "Password",
		6: "DepartmentName",
		7: "PositionName",
		8: "Phone",
		9: "Email",
	}
	excelData, invalidData, err := hashing.ExcelReaderByCreate(tempFile.Name(), fields, departmentMap, positionMap, employeeIDMap, emailMap)
	if err != nil {
		return 0, nil, web.NewRequestError(errors.Wrap(err, "reading excel data"), http.StatusBadRequest)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // Adjust as needed
	defer cancel()
	fmt.Println("Excell data:", excelData)
	var users []CreateResponse
	for _, data := range excelData {
		hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
		if err != nil {
			return 0, nil, web.NewRequestError(errors.Wrap(err, "hashing password"), http.StatusInternalServerError)
		}
		hashedPassword := string(hash)

		user := CreateResponse{
			EmployeeID:   &data.EmployeeID,
			Password:     &hashedPassword,
			Role:         data.Role,
			FirstName:    &data.FirstName,
			LastName:     &data.LastName,
			NickName:     data.NickName,
			DepartmentID: &data.DepartmentID,
			PositionID:   &data.PositionID,
			Phone:        &data.Phone,
			Email:        &data.Email,
			CreatedAt:    time.Now(),
			CreatedBy:    claims.UserId,
		}

		if err := r.ValidateStruct(&user); err != nil {
			return 0, nil, err
		}

		users = append(users, user)
	}

	const batchSize = 100

	var insertedCount int
	for i := 0; i < len(users); i += batchSize {
		end := i + batchSize
		if end > len(users) {
			end = len(users)
		}

		batch := users[i:end]
		_, err := r.NewInsert().Model(&batch).Exec(ctx)
		if err != nil {
			log.Printf("Failed to insert batch %d-%d: %v", i, end, err)
			continue // Skip to the next batch
		}
		insertedCount += len(batch)
	}

	// Count the created users
	return insertedCount, invalidData, nil
}
func (r Repository) UpdateByExcell(ctx context.Context, request ExcellRequest) (int, []submodel.InvalidUserResponse, error) {
	claims, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return 0,nil, err
	}

	departmentMap, err := r.LoadDepartmentMap(ctx)
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "loading department map"), http.StatusInternalServerError)
	}
	positionMap, err := r.LoadPositionMap(ctx)
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "loading position map"), http.StatusInternalServerError)
	}

	employeeIDMap := make(map[string]struct{})
	emailMap := make(map[string]struct{})

	rows, err := r.QueryContext(ctx,
		"SELECT employee_id, email FROM users WHERE role='EMPLOYEE' AND deleted_at IS NULL")
	if err != nil {
		return 0,nil, web.NewRequestError(
			errors.Wrap(err, "getting employee data"),
			http.StatusInternalServerError,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var employeeID, email string

		if err := rows.Scan(&employeeID, &email); err != nil {
			return 0,nil, web.NewRequestError(
				errors.Wrap(err, "scanning employee data"),
				http.StatusInternalServerError,
			)
		}

		// Employee ID ni mapga qo'shish
		employeeIDMap[employeeID] = struct{}{}

		// Email bo'sh bo'lmaganda mapga qo'shish
		if email != "" {
			emailMap[email] = struct{}{}
		}
	}

	// Iteratsiya xatolari uchun tekshirish
	if err := rows.Err(); err != nil {
		return 0,nil, web.NewRequestError(
			errors.Wrap(err, "database iteration error"),
			http.StatusInternalServerError,
		)
	}
	if err := r.ValidateStruct(request.Excell); err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "validating excel request"), http.StatusBadRequest)
	}

	file, err := request.Excell.Open()
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "opening excel file"), http.StatusBadRequest)
	}
	defer file.Close()

	tempFile, err := ioutil.TempFile("", "excel-*.xlsx")
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "creating temporary file"), http.StatusInternalServerError)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "copying excel file"), http.StatusInternalServerError)
	}
	fields := map[int]string{
		0: "EmployeeID",
		1: "LastName",
		2: "Firstname",
		3: "NickName",
		4: "Role",
		5: "Password",
		6: "DepartmentName",
		7: "PositionName",
		8: "Phone",
		9: "Email",
	}
	excelData, invalidData, err := hashing.ExcelReaderByEdit(tempFile.Name(), fields, departmentMap, positionMap, employeeIDMap, emailMap)
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "reading excel data"), http.StatusBadRequest)
	}

	// Start a transaction
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0,nil, web.NewRequestError(errors.Wrap(err, "starting transaction"), http.StatusInternalServerError)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // Adjust as needed
	defer cancel()

	createdCount := 0
	for _, data := range excelData {
		user := UpdateResponse{
			EmployeeID:   &data.EmployeeID,
			FirstName:    &data.FirstName,
			LastName:     &data.LastName,
			NickName:     &data.NickName,
			Role:         &data.Role,
			DepartmentID: &data.DepartmentID,
			PositionID:   &data.PositionID,
			Phone:        &data.Phone,
			Email:        &data.Email,
			UpdatedAt:    time.Now(),
			UpdatedBy:    claims.UserId,
		}

		if err := r.ValidateStruct(&user); err != nil {
			return 0,nil, err
		}

		q := r.NewUpdate().Table("users").Where("deleted_at IS NULL AND employee_id = ?", data.EmployeeID)

		if user.FirstName != nil {
			q.Set("first_name=?", data.FirstName)
		}
		if user.LastName != nil {
			q.Set("last_name=?", data.LastName)
		}
		if user.NickName != nil {
			q.Set("nick_name=?", data.NickName)
		}
		if user.Role != nil {
			q.Set("role=?", data.Role)
		}
		if user.DepartmentID != nil {
			q.Set("department_id=?", data.DepartmentID)
		}
		if user.PositionID != nil {
			q.Set("position_id=?", data.PositionID)
		}
		if user.Phone != nil {
			q.Set("phone=?", data.Phone)
		}
		if user.Email != nil {
			q.Set("email=?", data.Email)
		}
		q.Set("updated_at=?", time.Now())
		q.Set("updated_by=?", claims.UserId)

		// Execute the update query
		_, err = q.Exec(ctx)
		if err != nil {
			return 0,nil, web.NewRequestError(errors.Wrap(err, "updating user"), http.StatusBadRequest)
		}

		createdCount++
	}

	return createdCount, invalidData, nil
}

func (r Repository) DeleteByExcell(ctx context.Context, request ExcellRequest) (int, string, error) {
	_, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return 0,"", err
	}

	if err := r.ValidateStruct(request.Excell); err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "validating excel request"), http.StatusBadRequest)
	}

	file, err := request.Excell.Open()
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "opening excel file"), http.StatusBadRequest)
	}
	defer file.Close()

	tempFile, err := ioutil.TempFile("", "excel-*.xlsx")
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "creating temporary file"), http.StatusInternalServerError)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "copying excel file"), http.StatusInternalServerError)
	}

	fields := map[int]string{
		0: "EmployeeID",
		1: "FirstName",
		2: "LastName",
		3: "DepartmentName",
		4: "PositionName",
		5: "Phone",
		6: "Email",
	}
	rowLen := 7

	employeeIDs, incompleteRows, err := hashing.ExcelReaderByDelete(tempFile.Name(), rowLen, fields)
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "reading excel data"), http.StatusBadRequest)
	}

	if len(employeeIDs) == 0 {
		return 0, "", nil // No IDs to process
	}

	// Start a transaction
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "starting transaction"), http.StatusInternalServerError)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	// Format employee IDs for SQL query
	employeeIDList := "'" + strings.Join(employeeIDs, "', '") + "'"

	// Construct and execute the update query
	q := r.NewUpdate().Table("users").
		Set("deleted_at = NOW()").
		Where(fmt.Sprintf("deleted_at IS NULL AND employee_id IN (%s)", employeeIDList))

	result, err := q.Exec(ctx)
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "executing update query"), http.StatusInternalServerError)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, "", web.NewRequestError(errors.Wrap(err, "getting affected rows after update"), http.StatusInternalServerError)
	}

	return int(rowsAffected), incompleteRows, nil
}
func GenerateQRCode(employeeID string, filename string) error {
	// Generate the QR code
	qrCode, err := qrcode.New(employeeID, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("could not generate QR code for %s: %v", employeeID, err)
	}

	// Create an image with space for the text
	qrImage := qrCode.Image(512)
	textHeight := 5
	finalImage := image.NewRGBA(image.Rect(0, 0, qrImage.Bounds().Max.X, qrImage.Bounds().Max.Y+textHeight))

	// Draw the QR code
	draw.Draw(finalImage, qrImage.Bounds(), qrImage, image.Point{0, 0}, draw.Over)

	// Draw the employee ID text
	addLabel(finalImage, employeeID, qrImage.Bounds().Max.Y)

	// Save the final image to file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file %s: %v", filename, err)
	}
	defer file.Close()

	if err := png.Encode(file, finalImage); err != nil {
		return fmt.Errorf("could not encode PNG: %v", err)
	}

	return nil
}

func addLabel(img *image.RGBA, text string, yOffset int) {
	// Create a font drawer to measure the text width
	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.Black),
		Face: basicfont.Face7x13,
	}

	// Measure the width of the text
	textWidth := d.MeasureString(text).Ceil()

	// Set the position for the text (centered)
	pt := fixed.Point26_6{
		X: fixed.Int26_6((img.Bounds().Max.X - textWidth) / 2 << 6), // Centered X position
		Y: fixed.Int26_6((yOffset - 10) << 6),                       // Adjust Y position (raising the text)
	}

	// Draw the text
	d.Dot = pt
	d.DrawString(text)
}

// CreatePDF creates a PDF from a list of QR codes and numbers.
func CreatePDF(employeeIDs []string, pdfFilename string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "", 8)

	for _, employeeID := range employeeIDs {
		// Add employee ID text
		pdf.CellFormat(0, 5, employeeID, "", 1, "L", false, 0, "")

		// Add QR code image
		imagePath := fmt.Sprintf("qr_codes/%s.png", employeeID)
		pdf.ImageOptions(imagePath, 5, pdf.GetY(), 30, 30, false, gofpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}, 0, "")
		pdf.Ln(45)
	}

	err := pdf.OutputFileAndClose(pdfFilename)
	if err != nil {
		return fmt.Errorf("could not create PDF: %v", err)
	}

	return nil
}

func (r *Repository) GetQrCodeByEmployeeID(ctx context.Context, employeeID string) (string, error) {
	_, err := r.CheckClaims(ctx, auth.RoleAdmin)
	if err != nil {
		return "", err
	}
	// Define the directory and filename
	dir := "qr_codes"
	filename := filepath.Join(dir, fmt.Sprintf("%s.png", employeeID))

	// Check if the directory exists, create if it doesn't
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", fmt.Errorf("could not create directory %s: %v", dir, err)
	}

	// Generate the QR code
	if err := GenerateQRCode(employeeID, filename); err != nil {
		return "", err
	}

	fmt.Printf("QR code for employee ID %s saved to %s\n", employeeID, filename)
	return filename, nil
}

func (r *Repository) GetQrCodeList(ctx context.Context) (string, error) {
	rows, err := r.Query("SELECT employee_id FROM users WHERE deleted_at IS NULL AND role='EMPLOYEE'")
	if err != nil {
		return "", fmt.Errorf("failed to query employee IDs: %v", err)
	}
	defer rows.Close()

	var employeeIDs []string
	for rows.Next() {
		var employeeID string
		if err := rows.Scan(&employeeID); err != nil {
			return "", fmt.Errorf("failed to scan employee ID: %v", err)
		}
		employeeIDs = append(employeeIDs, employeeID)
	}

	if err := os.MkdirAll("qr_codes", os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	for _, employeeID := range employeeIDs {
		filename := fmt.Sprintf("qr_codes/%s.png", employeeID)
		if err := GenerateQRCode(employeeID, filename); err != nil {
			log.Printf("Error generating QR code for %s: %v", employeeID, err)
		}
	}

	pdfFilename := "qr_employees.pdf"
	if err := CreatePDF(employeeIDs, pdfFilename); err != nil {
		return "", fmt.Errorf("failed to create PDF: %v", err)
	}

	return pdfFilename, nil
}

func (r Repository) GetMonthlyStatistics(ctx context.Context, request MonthlyStatisticRequest) (MonthlyStatisticResponse, error) {
	claims, err := r.CheckClaims(ctx)
	if err != nil {
		return MonthlyStatisticResponse{}, web.NewRequestError(errors.New("error getting user by token"), http.StatusBadRequest)
	}

	// Calculate the start and end dates of the month
	startDate := request.Month
	endDate := startDate.AddDate(0, 1, -1) // Last day of the month

	// Convert dates to strings in the format 'YYYY-MM-DD'
	startDateStr := startDate.Format("2006-01-02")
	endDateStr := endDate.Format("2006-01-02")

	// Initialize the response with 0 values
	list := MonthlyStatisticResponse{
		EarlyCome:  new(int),
		EarlyLeave: new(int),
		Absent:     new(int),
		Late:       new(int),
	}

	// Query for monthly statistics
	monthlyQuery := `
		SELECT
			COALESCE(SUM(CASE WHEN a.come_time <= '09:00' THEN 1 ELSE 0 END), 0) AS early_come,
			COALESCE(SUM(CASE WHEN a.leave_time < '18:00' THEN 1 ELSE 0 END), 0) AS early_leave,
			COALESCE(SUM(CASE WHEN u.status = 'false' THEN 1 ELSE 0 END), 0) AS absent,
			COALESCE(SUM(CASE WHEN a.come_time >= '10:00' THEN 1 ELSE 0 END), 0) AS late
		FROM attendance a
		JOIN users u ON a.employee_id = u.employee_id
		WHERE a.deleted_at IS NULL
		AND u.id = $1
		AND a.work_day BETWEEN $2 AND $3;
	`

	monthlyStmt, err := r.Prepare(monthlyQuery)
	if err != nil {
		return MonthlyStatisticResponse{}, web.NewRequestError(errors.Wrap(err, "preparing monthly query"), http.StatusInternalServerError)
	}
	defer monthlyStmt.Close()
	err = monthlyStmt.QueryRowContext(ctx, claims.UserId, startDateStr, endDateStr).Scan(
		list.EarlyCome,
		list.EarlyLeave,
		list.Absent,
		list.Late,
	)
	if err != nil {
		return MonthlyStatisticResponse{}, web.NewRequestError(errors.Wrap(err, "scanning monthly statistics"), http.StatusInternalServerError)
	}

	return list, nil
}

func (r Repository) GetStatistics(ctx context.Context, filter StatisticRequest) ([]StatisticResponse, error) {
	claims, err := r.CheckClaims(ctx)
	if err != nil {
		return nil, web.NewRequestError(errors.New("error getting user by token"), http.StatusBadRequest)
	}

	// Determine the start and end days based on the interval
	var startDay, endDay int
	switch filter.Interval {
	case 0:
		startDay, endDay = 1, 10
	case 1:
		startDay, endDay = 11, 20
	case 2:
		startDay, endDay = 21, 31 // Adjust for months with fewer than 31 days later
	default:
		return nil, web.NewRequestError(errors.New("invalid interval"), http.StatusBadRequest)
	}

	// Calculate start and end dates for the interval
	startDate := time.Date(filter.Month.Year(), filter.Month.Month(), startDay, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(filter.Month.Year(), filter.Month.Month(), endDay, 23, 59, 59, 999999999, time.UTC)

	// Generate all dates within the interval
	var allDates []time.Time
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		allDates = append(allDates, d)
	}

	// Query for interval data
	intervalQuery := `
		SELECT
			a.work_day,
			COALESCE(TO_CHAR(a.come_time, 'HH24:MI'), '00:00') AS come_time,
			COALESCE(TO_CHAR(a.leave_time, 'HH24:MI'), '00:00') AS leave_time,
			COALESCE(SUM(EXTRACT(EPOCH FROM (ap.leave_time - ap.come_time)) / 60), 0) AS total_minutes
		FROM attendance a
		JOIN users u ON a.employee_id = u.employee_id
		LEFT JOIN attendance_period ap ON a.id = ap.attendance_id
		WHERE a.deleted_at IS NULL
			AND u.id = $1
			AND a.work_day BETWEEN $2 AND $3
		GROUP BY a.work_day, a.come_time, a.leave_time
		ORDER BY a.work_day;
	`

	// Execute interval query
	intervalStmt, err := r.Prepare(intervalQuery)
	if err != nil {
		return nil, web.NewRequestError(errors.Wrap(err, "preparing interval query"), http.StatusInternalServerError)
	}
	defer intervalStmt.Close()

	rows, err := intervalStmt.QueryContext(ctx, claims.UserId, startDate, endDate)
	if err != nil {
		return nil, web.NewRequestError(errors.Wrap(err, "executing interval query"), http.StatusInternalServerError)
	}
	defer rows.Close()

	// Map to store retrieved data by date
	dataMap := make(map[string]StatisticResponse)
	for rows.Next() {
		var detail StatisticResponse
		var totalMinutes float64
		err := rows.Scan(
			&detail.WorkDay,
			&detail.ComeTime,
			&detail.LeaveTime,
			&totalMinutes,
		)
		if err != nil {
			return nil, web.NewRequestError(errors.Wrap(err, "scanning interval statistics"), http.StatusInternalServerError)
		}

		// Convert total minutes to HH:MM
		hours := int(totalMinutes) / 60
		minutes := int(totalMinutes) % 60
		detail.TotalHours = fmt.Sprintf("%02d:%02d", hours, minutes)
		dataMap[*detail.WorkDay] = detail
	}

	// Generate the final list of responses, filling in missing dates with default values
	var list []StatisticResponse
	for _, date := range allDates {
		dateStr := date.Format("2006-01-02")
		if data, found := dataMap[dateStr]; found {
			list = append(list, data)
		} else {
			list = append(list, StatisticResponse{
				WorkDay:    &dateStr,
				ComeTime:   ptr("00:00"),
				LeaveTime:  ptr("00:00"),
				TotalHours: "00:00",
			})
		}
	}

	return list, nil
}

// Utility function to return a pointer to a string
func ptr(s string) *string {
	return &s
}

func (r Repository) GetEmployeeDashboard(ctx context.Context) (DashboardResponse, error) {
	claims, err := r.CheckClaims(ctx, auth.RoleEmployee)
	if err != nil {
		return DashboardResponse{}, err
	}
	loc, _ := time.LoadLocation("Asia/Tokyo")
	currentTime := time.Now().In(loc) // Yapon vaqtini olamiz
	workDay := currentTime.Format("2006-01-02")

	var detail DashboardResponse
	var totalMinutes int
	query := fmt.Sprintf(`
        SELECT
   		 MAX(ap.come_time) AS come_time,  -- Use MAX to get the latest come_time
   		 MAX(a.leave_time) AS leave_time, -- Use MAX to get the latest leave_time
    		COALESCE(SUM(EXTRACT(EPOCH FROM (ap.leave_time - ap.come_time))/ 60)::INT, 0) AS total_hours
		FROM attendance AS a
		JOIN users AS u ON u.employee_id = a.employee_id
		JOIN attendance_period AS ap ON ap.attendance_id = a.id
		WHERE a.work_day= '%s'
		AND ap.work_day= '%s'
		AND a.deleted_at IS NULL
		AND u.deleted_at IS NULL
		AND u.id = %d
		GROUP BY a.employee_id
		ORDER BY come_time DESC
		LIMIT 1;            
	`, workDay, workDay, claims.UserId)
	err = r.QueryRowContext(ctx, query).Scan(
		&detail.ComeTime,
		&detail.LeaveTime,
		&totalMinutes,
	)

	hours := totalMinutes / 60
	minutes := totalMinutes % 60
	totalHours := fmt.Sprintf("%02d:%02d", hours, minutes)
	detail.TotalHours = totalHours
	if errors.Is(err, sql.ErrNoRows) {
		return DashboardResponse{}, nil
	}
	if err != nil {
		return DashboardResponse{}, web.NewRequestError(errors.Wrap(err, "selecting user detail on dashboard"), http.StatusBadRequest)
	}
	return detail, nil
}

func (r Repository) GetDashboardList(ctx context.Context, filter Filter) ([]DepartmentResult, int, error) {
	// Pagination queries
	var limitQuery, offsetQuery string
	if filter.Page != nil && filter.Limit != nil {
		offset := (*filter.Page - 1) * (*filter.Limit)
		filter.Offset = &offset
	}
	if filter.Limit != nil {
		limitQuery = fmt.Sprintf(" LIMIT %d", *filter.Limit)
	}
	if filter.Offset != nil {
		offsetQuery = fmt.Sprintf(" OFFSET %d", *filter.Offset)
	}

	loc, _ := time.LoadLocation("Asia/Tokyo")
	currentTime := time.Now().In(loc) // Yapon vaqtini olamiz
	workDay := currentTime.Format("2006-01-02")
	query := fmt.Sprintf(`

                 SELECT
                    u.id,
                    u.employee_id,
                    u.last_name,
					u.nick_name,
                    COALESCE(a.status, false) AS status,
                    d.id AS department_id,
                    d.name AS department_name,
					d.department_nickname,
                    d.display_number
                FROM
                       department AS d
                   LEFT JOIN users AS u ON d.id = u.department_id AND u.deleted_at IS NULL
                   LEFT JOIN (
                       SELECT
                           a.employee_id,
                           COALESCE(a.status, false) AS status
                       FROM
                           attendance AS a
                       WHERE
                           a.work_day = '%s'  AND a.deleted_at IS NULL
                   ) AS a ON a.employee_id = u.employee_id
                   WHERE    d.deleted_at IS NULL
                   ORDER BY   d.display_number ASC %s %s`, workDay, limitQuery, offsetQuery)

	rows, err := r.QueryContext(ctx, query)
	if err != nil {
		return nil, 0, web.NewRequestError(errors.Wrap(err, "querying employee dashboard list"), http.StatusBadRequest)
	}
	defer rows.Close()

	// Map to store departments with employees grouped
	departmentMap := make(map[int]*DepartmentResult)

	for rows.Next() {
		var (
			detail             GetDashboardlist
			departmentID       int
			displayNumber      sql.NullInt64
			userID             sql.NullInt64
			departmentName     sql.NullString
			departmentNickName sql.NullString

			nickName sql.NullString
		)

		// Scan the row with individual fields
		err = rows.Scan(
			&userID,
			&detail.EmployeeID,
			&detail.LastName,
			&nickName,
			&detail.Status,
			&departmentID,
			&departmentName,
			&departmentNickName,
			&displayNumber,
		)
		detail.DepartmentID = &departmentID

		if err != nil {
			return nil, 0, web.NewRequestError(errors.Wrap(err, "scanning dashboard employee list"), http.StatusBadRequest)
		}

		if nickName.Valid {
			detail.NickName = nickName.String
		} else {
			detail.NickName = ""
		}
		if departmentName.Valid {
			detail.DepartmentName = &departmentName.String
		}
		if departmentNickName.Valid {
			detail.DepartmentNickName = departmentNickName.String
		} else {
			detail.NickName = ""
		}
		if displayNumber.Valid {
			dn := int(displayNumber.Int64)
			detail.DisplayNumber = &dn
		}

		if userID.Valid {
			dn := int(userID.Int64)
			detail.ID = &dn
		}
		// Group employees by department
		if detail.DepartmentID != nil {
			if deptResult, exists := departmentMap[*detail.DepartmentID]; exists {
				deptResult.Employees = append(deptResult.Employees, detail)
			} else {
				departmentMap[*detail.DepartmentID] = &DepartmentResult{
					DepartmentName:     detail.DepartmentName,
					DisplayNumber:      *detail.DisplayNumber,
					DepartmentNickName: detail.DepartmentNickName,
					Employees:          []GetDashboardlist{detail},
				}
			}
		}

	}

	// Convert map to slice and sort by DisplayNumber
	var results []DepartmentResult
	for _, dept := range departmentMap {
		results = append(results, *dept)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].DisplayNumber < results[j].DisplayNumber
	})

	// Total count query
	countQuery := fmt.Sprintf(`
        SELECT
            count(u.employee_id)
        FROM
            users AS u
        LEFT JOIN
            attendance AS a ON a.employee_id = u.employee_id AND a.work_day = '%s'
		RIGHT JOIN department as d on d.id=u.department_id AND d.deleted_at IS NULL	
        WHERE
            u.deleted_at IS NULL AND
            u.role = 'EMPLOYEE';`, workDay)

	countRows, err := r.QueryContext(ctx, countQuery)
	if err != nil {
		return nil, 0, web.NewRequestError(errors.Wrap(err, "selecting users"), http.StatusBadRequest)
	}
	defer countRows.Close()

	// Get total count
	count := 0
	for countRows.Next() {
		if err = countRows.Scan(&count); err != nil {
			return nil, 0, web.NewRequestError(errors.Wrap(err, "scanning user count"), http.StatusBadRequest)
		}
	}

	return results, count, nil
}

func (r *Repository) ExportEmployee(ctx context.Context) (string, error) {
	query := `
	SELECT 
		u.employee_id,
		u.last_name,
		u.first_name,
		u.nick_name,
		u.role,
		d.name as department_name,
		p.name as position_name,
		u.phone,
		u.email
	FROM users u
	JOIN department d ON d.id = u.department_id AND d.deleted_at IS NULL
	JOIN position p ON p.id = u.position_id AND p.deleted_at IS NULL
	WHERE u.deleted_at IS NULL AND u.role = 'EMPLOYEE'
	ORDER BY u.employee_id DESC;
`

	rows, err := r.Query(query)
	if err != nil {
		return "", fmt.Errorf("failed to export employee list: %v", err)
	}
	defer rows.Close()

	var list []service.Employee // Use the Employee type from the service package

	for rows.Next() {
		var detail service.Employee // Use the Employee type from the service package
		var nickName sql.NullString
		var firstName sql.NullString
		var lastName sql.NullString
		var phone sql.NullString

		if err = rows.Scan(
			&detail.EmployeeID,
			&lastName,
			&firstName,
			&nickName,
			&detail.Role,
			&detail.DepartmentName,
			&detail.PositionName,
			&phone,
			&detail.Email); err != nil {
			return "", web.NewRequestError(errors.Wrap(err, "scanning user list"), http.StatusBadRequest)
		}
		if nickName.Valid {
			detail.NickName = nickName.String
		} else {
			detail.NickName = ""
		}
		if firstName.Valid {
			detail.FirstName = firstName.String
		} else {
			detail.FirstName = ""
		}
		if lastName.Valid {
			detail.LastName = lastName.String
		} else {
			detail.LastName = ""
		}
		if phone.Valid {
			detail.Phone = phone.String
		} else {
			detail.Phone = ""
		}

		list = append(list, detail)
	}
	departments := []string{}
	positions := []string{}

	query = `SELECT name FROM department  where deleted_at is null  ORDER BY display_number ASC`
	err = r.NewRaw(query).Scan(ctx, &departments)
	if err != nil {
		return "", web.NewRequestError(errors.Wrap(err, "fetching departments list"), http.StatusInternalServerError)
	}

	queryy := `SELECT name FROM position  where deleted_at is null `
	err = r.NewRaw(queryy).Scan(ctx, &positions)
	if err != nil {
		return "", web.NewRequestError(errors.Wrap(err, "fetching position list"), http.StatusInternalServerError)
	}

	file, err := service.AddDataToExcel(list, departments, positions)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	return file, nil

}

func (r Repository) ExportTemplate(ctx context.Context) (string, error) {
	departments := []string{}
	positions := []string{}

	query := `SELECT name FROM department  where deleted_at is null  ORDER BY display_number ASC`
	err := r.NewRaw(query).Scan(ctx, &departments)
	if err != nil {
		return "", web.NewRequestError(errors.Wrap(err, "fetching departments list"), http.StatusInternalServerError)
	}

	queryy := `SELECT name FROM position  where deleted_at is null `
	err = r.NewRaw(queryy).Scan(ctx, &positions)
	if err != nil {
		return "", web.NewRequestError(errors.Wrap(err, "fetching position list"), http.StatusInternalServerError)
	}
	file, err := hashing.EditExcell(departments, positions)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	return file, nil
}

type GetDepartmentListResponse struct {
	ID            int     `json:"id"`
	Name          *string `json:"name"`
	DisplayNumber int     `json:"display_number"`
}

func (r Repository) LoadDepartmentMap(ctx context.Context) (map[string]int, error) {
	departmentMap := make(map[string]int)
	var departments []GetDepartmentListResponse

	query := `
			SELECT 
			id,
			name
		FROM department
		WHERE deleted_at IS NULL`

	rows, err := r.DB.QueryContext(ctx, query)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
		}
		return nil, web.NewRequestError(errors.Wrap(err, "selecting department"), http.StatusBadRequest)
	}
	defer rows.Close()

	for rows.Next() {
		var detail GetDepartmentListResponse
		if err := rows.Scan(&detail.ID, &detail.Name); err != nil {
			return nil, web.NewRequestError(errors.Wrap(err, "scanning department"), http.StatusBadRequest)
		}
		departments = append(departments, detail)
	}

	if err := rows.Err(); err != nil {
		return nil, web.NewRequestError(errors.Wrap(err, "reading rows"), http.StatusInternalServerError)
	}

	for _, dept := range departments {
		if dept.Name != nil {
			departmentMap[*dept.Name] = dept.ID
		}
	}
	return departmentMap, nil
}

type GetPositionListResponse struct {
	ID           int     `json:"id"`
	Name         *string `json:"name"`
	DepartmentID *int    `json:"department_id"`
	Department   *string `json:"department"`
}

func (r Repository) LoadPositionMap(ctx context.Context) (map[string]int, error) {
	positionMap := make(map[string]int)
	var positions []GetPositionListResponse

	query := `
		SELECT 
		id,
		name
	FROM position
	WHERE deleted_at IS NULL`

	rows, err := r.DB.QueryContext(ctx, query)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, web.NewRequestError(postgres.ErrNotFound, http.StatusBadRequest)
		}
		return nil, web.NewRequestError(errors.Wrap(err, "selecting position"), http.StatusBadRequest)
	}
	defer rows.Close()

	for rows.Next() {
		var detail GetPositionListResponse
		if err := rows.Scan(&detail.ID, &detail.Name); err != nil {
			return nil, web.NewRequestError(errors.Wrap(err, "scanning position"), http.StatusBadRequest)
		}
		positions = append(positions, detail)
	}

	if err := rows.Err(); err != nil {
		return nil, web.NewRequestError(errors.Wrap(err, "reading rows"), http.StatusInternalServerError)
	}

	for _, dept := range positions {
		if dept.Name != nil {
			positionMap[*dept.Name] = dept.ID
		}
	}

	return positionMap, nil
}
