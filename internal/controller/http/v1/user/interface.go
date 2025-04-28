package user

import (
	"attendance/backend/internal/repository/postgres/companyInfo"
	submodel "attendance/backend/internal/repository/postgres/sub_model"
	"attendance/backend/internal/repository/postgres/user"
	"context"
)

type User interface {
	GetList(ctx context.Context, filter user.Filter) ([]user.GetListResponse, int, error)
	GetStatistics(ctx context.Context, filter user.StatisticRequest) ([]user.StatisticResponse, error)
	GetMonthlyStatistics(ctx context.Context, filter user.MonthlyStatisticRequest) (user.MonthlyStatisticResponse, error)
	GetEmployeeDashboard(ctx context.Context) (user.DashboardResponse, error)
	GetDetailById(ctx context.Context, id int) (user.GetDetailByIdResponse, error)
	GetQrCodeByEmployeeID(ctx context.Context, emloyee_id string) (string, error)
	GetQrCodeList(ctx context.Context) (string, error)
	GetDashboardList(ctx context.Context, filter user.Filter) ([]user.DepartmentResult, int, error)
	GetFullName(ctx context.Context) (user.GetFullName, error)

	Create(ctx context.Context, request user.CreateRequest) (user.CreateResponse, error)
	CreateByExcell(ctx context.Context, request user.ExcellRequest) (int, []submodel.InvalidUserResponse, error)
	UpdateByExcell(ctx context.Context, request user.ExcellRequest) (int, []submodel.InvalidUserResponse, error)
	DeleteByExcell(ctx context.Context, request user.ExcellRequest) (int, string, error)
	ExportEmployee(ctx context.Context) (string, error)
	ExportTemplate(ctx context.Context) (string, error)
	UpdateColumns(ctx context.Context, request user.UpdateRequest) error
	Delete(ctx context.Context, id int) error
}
type CompanyInfo interface {
	GetNewTableColor(ctx context.Context) (companyInfo.GetNewTableColorResponse, error)
}
