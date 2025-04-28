package submodel

type UserRow struct {
	EmployeeID     string `json:"employee_id"`
	LastName       string `json:"last_name"`
	FirstName      string `json:"first_name"`
	NickName       string `json:"nick_name,omitempty"`
	Role           string `json:"role"`
	Password       string `json:"password"`
	DepartmentName string `json:"department_name"`
	PositionName   string `json:"position_name"`
	Phone          string `json:"phone,omitempty"`
	Email          string `json:"email,omitempty"`
}

type UserErrors struct {
	EmployeeID     string `json:"employee_id,omitempty"`
	LastName       string `json:"last_name,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	Role           string `json:"role,omitempty"`
	Password       string `json:"password,omitempty"`
	DepartmentName string `json:"department_name,omitempty"`
	PositionName   string `json:"position_name,omitempty"`
	Phone          string `json:"phone,omitempty"`
	Email          string `json:"email,omitempty"`
}

type InvalidUserResponse struct {
	Row    UserRow    `json:"row"`
	Errors UserErrors `json:"errors"`
}
