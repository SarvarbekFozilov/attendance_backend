package user

import (
	"mime/multipart"
	"time"

	"github.com/Azure/go-autorest/autorest/date"
	"github.com/uptrace/bun"
)

type Filter struct {
	Limit        *int
	Offset       *int
	Page         *int
	Search       *string
	DepartmentID *int
	PositionID   *int
}

type SignInRequest struct {
	Password   string `json:"password" form:"password"`
	EmployeeID string `json:"employee_id" form:"employee_id"`
}

type AuthClaims struct {
	ID   int
	Role string
	Type string
}

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token" form:"access_token"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
}

type GetListResponse struct {
	ID           int     `json:"id"`
	EmployeeID   *string `json:"employee_id"`
	FullName     *string `json:"full_name"`
	NickName     string  `json:"nick_name"`
	DepartmentID *int    `json:"department_id"`
	Department   *string `json:"department"`
	PositionID   *int    `json:"position_id"`
	Position     *string `json:"position"`
	Phone        *string `json:"phone"`
	Email        *string `json:"email"`
}

  
type GetDetailByIdResponse struct {
	ID           int     `json:"id"`
	EmployeeID   *string `json:"employee_id"`
	FullName     *string `json:"full_name"`
	NickName     string  `json:"nick_name"`
	DepartmentID *int    `json:"department_id"`
	Department   *string `json:"department"`
	PositionID   *int    `json:"position_id"`
	Position     *string `json:"position"`
	Phone        *string `json:"phone"`
	Email        *string `json:"email"`
}

type ExcellRequest struct {
	Mode   int                   `json:"mode" form:"mode"`
	Excell *multipart.FileHeader `json:"-" form:"excell"`
}
type ExcellUpload struct {
	Excell *multipart.FileHeader `json:"-" form:"excell"`
	Url    string                `json:"url" form:"-"`
}
type DepartmentResult struct {
	DepartmentName     *string            `json:"department_name"`
	DisplayNumber      int                `json:"display_number"`
	DepartmentNickName string             `json:"department_nickname"`
	Employees          []GetDashboardlist `json:"result"`
}
type GetDashboardlist struct {
	ID                 *int    `json:"id"`
	EmployeeID         *string `json:"employee_id"`
	DepartmentID       *int    `json:"department_id"`
	DepartmentName     *string `json:"department_name"`     // Use sql.NullString
	DepartmentNickName string  `json:"department_nickname"` // Use sql.NullString
	DisplayNumber      *int    `json:"display_number"`      // Use sql.NullInt32
	LastName           *string `json:"last_name"`
	NickName           string  `json:"nick_name"`
	Status             *bool   `json:"status"`
}

type GetDepartmentlist struct {
	DepartmentName *string `json:"department"`
	DisplayNumber  int     `json:"display_number"`
	EmployeeCount  *string `json:"employee_count"`
}
type GetFullName struct {
	bun.BaseModel `bun:"table:users"`

	FullName   *string `json:"full_name"`
	EmployeeID *string `json:employee_id"`
}

type CreateResponse struct {
	bun.BaseModel `bun:"table:users"`

	ID           int       `json:"id" bun:"-"`
	EmployeeID   *string   `json:"employee_id"   bun:"employee_id"`
	Password     *string   `json:"-"   bun:"password"`
	Role         string    `json:"role" bun:"role"`
	FirstName    *string   `json:"first_name"  bun:"first_name"`
	LastName     *string   `json:"last_name"  form:"last_name"`
	NickName     string    `json:"nick_name" bun:"nick_name"`
	DepartmentID *int      `json:"department_id" bun:"department_id"`
	PositionID   *int      `json:"position_id" bun:"position_id"`
	Phone        *string   `json:"phone" bun:"phone"`
	Email        *string   `json:"email" bun:"email"`
	CreatedAt    time.Time `json:"-"          bun:"created_at"`
	CreatedBy    int       `json:"-"          bun:"created_by"`
}
type UpdateResponse struct {
	bun.BaseModel `bun:"table:users"`

	EmployeeID   *string   `json:"employee_id"   bun:"employee_id"`
	FirstName    *string   `json:"first_name"  bun:"first_name"`
	LastName     *string   `json:"last_name"  bun:"last_name"`
	NickName     *string   `json:"nick_name"  bun:"nick_name"`
	Role         *string   `json:"role" bun:"role"`
	DepartmentID *int      `json:"department_id" bun:"department_id"`
	PositionID   *int      `json:"position_id" bun:"position_id"`
	Phone        *string   `json:"phone" bun:"phone"`
	Email        *string   `json:"email" bun:"email"`
	UpdatedAt    time.Time `json:"-"          bun:"created_at"`
	UpdatedBy    int       `json:"-"          bun:"created_by"`
}
type IncompleteUser struct {
	Data   []CreateRequest
	Reason string
}

type CreateRequest struct {
	EmployeeID   *string `json:"employee_id"   form:"employee_id"`
	Password     *string `json:"password"   form:"password"`
	Role         *string `json:"role" form:"role"`
	FirstName    *string `json:"first_name"  form:"first_name"`
	LastName     *string `json:"last_name"  form:"last_name"`
	NickName     string  `json:"nick_name"  form:"nick_name"`
	DepartmentID *int    `json:"department_id" form:"department_id"`
	PositionID   *int    `json:"position_id" form:"position_id"`
	Phone        *string `json:"phone" form:"phone"`
	Email        *string `json:"email" form:"email"`
}
type GenEmployeeID struct {
	bun.BaseModel `bun:"table:users"`

	ID         int     `json:"id" bun:"-"`
	EmployeeID *string `json:"employee_id"   bun:"employee_id"`
	FullName   *string `json:"full_name"  bun:"full_name"`
}

type UpdateRequest struct {
	ID           int     `json:"id" form:"id"`
	EmployeeID   *string `json:"employee_id"   form:"employee_id"`
	Password     string  `json:"password"   form:"password"`
	Role         *string `json:"role"       form:"role"`
	FirstName    *string `json:"first_name"  form:"first_name"`
	LastName     *string `json:"last_name"  form:"last_name"`
	NickName     *string `json:"nick_name"  form:"nick_name"`
	DepartmentID *int    `json:"department_id" form:"department_id"`
	PositionID   *int    `json:"position_id" form:"position_id"`
	Phone        *string `json:"phone" form:"phone"`
	Email        *string `json:"email" form:"email"`
}
type StatisticRequest struct {
	Month    date.Date
	Interval int
}

type StatisticResponse struct {
	WorkDay    *string `json:"work_day" bun:"work_day"`
	ComeTime   *string `json:"come_time" bun:"come_time"`
	LeaveTime  *string `json:"leave_time,omitempty" bun:"leave_time"`
	TotalHours string  `json:"total_hours" bun:"total_hours"`
}
type DashboardResponse struct {
	ComeTime   *string `json:"come_time" bun:"come_time"`
	LeaveTime  *string `json:"leave_time" bun:"leave_time"`
	TotalHours string  `json:"total_hours" bun:"total_hours"`
}
type MonthlyStatisticRequest struct {
	Month date.Date
}
type MonthlyStatisticResponse struct {
	EarlyCome  *int `json:"early_come" bun:"early_come"`
	EarlyLeave *int `json:"early_leave" bun:"early_leave"`
	Absent     *int `json:"absent" bun:"absent"`
	Late       *int `json:"late" bun:"late"`
}
