package router

import (
	"attendance/backend/docs"
	"attendance/backend/foundation/web"
	"attendance/backend/internal/auth"
	"attendance/backend/internal/controller/http/v1/file"
	"attendance/backend/internal/repository/postgres/attendance"
	"attendance/backend/internal/repository/postgres/companyInfo"
	"attendance/backend/internal/repository/postgres/department"
	"attendance/backend/internal/repository/postgres/position"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"attendance/backend/internal/middleware"
	"attendance/backend/internal/pkg/repository/postgresql"

	"attendance/backend/internal/repository/postgres/user"

	attendance_controller "attendance/backend/internal/controller/http/v1/attendance"
	auth_controller "attendance/backend/internal/controller/http/v1/auth"
	companyInfo_controller "attendance/backend/internal/controller/http/v1/companyInfo"
	department_controller "attendance/backend/internal/controller/http/v1/department"
	position_controller "attendance/backend/internal/controller/http/v1/position"
	user_controller "attendance/backend/internal/controller/http/v1/user"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type Router struct {
	*web.App
	postgresDB         *postgresql.Database
	redisDB            *redis.Client
	port               string
	auth               *auth.Auth
	fileServerBasePath string
}

func NewRouter(
	app *web.App,
	postgresDB *postgresql.Database,
	redisDB *redis.Client,
	port string,
	auth *auth.Auth,
	fileServerBasePath string,
) *Router {
	return &Router{
		app,
		postgresDB,
		redisDB,
		port,
		auth,
		fileServerBasePath,
	}
}

func (r Router) Init() error {


	// r.Use(middleware.CORS())         <- to work on localhost

	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler), func(ctx *gin.Context) {
		docs.SwaggerInfo.Host = ctx.Request.Host
		if ctx.Request.TLS != nil {
			docs.SwaggerInfo.Schemes = []string{"https"}
		}
	})

	// - postgresql
	userPostgres := user.NewRepository(r.postgresDB)
	departmentPostgres := department.NewRepository(r.postgresDB)
	positionPostgres := position.NewRepository(r.postgresDB)
	companyInfoPostgres := companyInfo.NewRepository(r.postgresDB)
	attendancePostgres := attendance.NewRepository(r.postgresDB)

	// controller
	userController := user_controller.NewController(userPostgres, companyInfoPostgres)
	authController := auth_controller.NewController(userPostgres)
	departmentController := department_controller.NewController(departmentPostgres)
	positionController := position_controller.NewController(positionPostgres)
	companyInfoController := companyInfo_controller.NewController(companyInfoPostgres)

	attendanceController := attendance_controller.NewController(attendancePostgres, companyInfoPostgres)

	fileC := file.NewController(r.App, r.fileServerBasePath)

	// #auth
	r.Post("/api/v1/sign-in", authController.SignIn)
	r.Post("/api/v1/refresh-token", authController.RefreshToken)

	r.GET("/media/*filepath", fileC.File)
	r.HEAD("/media/*filepath", fileC.File)

	// #user
	r.Get("/api/v1/user/list", userController.GetUserList, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/:id", userController.GetUserDetailById, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/qrcode", userController.GetQrCodeByEmployeeId, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/qrcodelist", userController.GetQrCodeList, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/export_employee", userController.ExportEmployee, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/export_template", userController.ExportTemplate, middleware.Authenticate(r.auth, auth.RoleAdmin))

	r.Post("/api/v1/user/create", userController.CreateUser, middleware.Authenticate(r.auth, auth.RoleAdmin), middleware.ValidateEmailAndPhoneInput(), middleware.ValidateHalfWidthInput())
	r.Post("/api/v1/user/create_excell", userController.CreateUserByExcell, middleware.Authenticate(r.auth, auth.RoleAdmin))

	r.Patch("/api/v1/user/:id", userController.UpdateUserColumns, middleware.Authenticate(r.auth, auth.RoleAdmin), middleware.ValidateEmailAndPhoneInput(), middleware.ValidateHalfWidthInput())
	r.Delete("/api/v1/user/:id", userController.DeleteUser, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/user/statistics", userController.GetStatistics, middleware.Authenticate(r.auth))
	r.Get("/api/v1/user/monthly", userController.GetMonthlyStatistics, middleware.Authenticate(r.auth))
	r.Get("/api/v1/user/dashboard", userController.GetEmployeeDashboard, middleware.Authenticate(r.auth))
	r.GET("/api/v1/user/dashboardlist", func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		log.Println("WebSocket route hit")
		userController.GetDashboardListSSE(w, r)
	})

	// #department
	r.Get("/api/v1/department/list", departmentController.GetList, middleware.Authenticate(r.auth, auth.RoleAdmin, auth.RoleDashboard))
	r.Get("/api/v1/department/:id", departmentController.GetDetailById, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Post("/api/v1/department/create", departmentController.Create, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Patch("/api/v1/department/:id", departmentController.UpdateColumns, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Delete("/api/v1/department/:id", departmentController.Delete, middleware.Authenticate(r.auth, auth.RoleAdmin))

	// #position
	r.Get("/api/v1/position/list", positionController.GetList, middleware.Authenticate(r.auth, auth.RoleAdmin, auth.RoleDashboard))
	r.Get("/api/v1/position/:id", positionController.GetDetailById, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Post("/api/v1/position/create", positionController.Create, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Put("/api/v1/position/:id", positionController.UpdateAll, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Patch("/api/v1/position/:id", positionController.UpdateColumns, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Delete("/api/v1/position/:id", positionController.Delete, middleware.Authenticate(r.auth, auth.RoleAdmin))
	// #companyInfo
	r.Get("/api/v1/company_info/list", companyInfoController.GetInfo, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Put("/api/v1/company_info/:id", companyInfoController.UpdateAll, middleware.Authenticate(r.auth, auth.RoleAdmin), middleware.ValidateHalfWidthInput())

	// #attendance
	r.Get("/api/v1/attendance/list", attendanceController.GetList, middleware.Authenticate(r.auth, auth.RoleAdmin, auth.RoleEmployee, auth.RoleDashboard))
	r.Get("/api/v1/attendance/:id", attendanceController.GetDetailById, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/attendance/history", attendanceController.GetHistoryById, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Post("/api/v1/attendance/createbyphone", attendanceController.CreateByPhone, middleware.Authenticate(r.auth))
	r.Post("/api/v1/attendance/createbyqrcode", attendanceController.CreateByQRCode, middleware.Authenticate(r.auth))
	r.Patch("/api/v1/attendance/exitbyphone", attendanceController.ExitByPhone, middleware.Authenticate(r.auth))
	r.Put("/api/v1/attendance/:id", attendanceController.UpdateAll, middleware.Authenticate(r.auth, auth.RoleAdmin), middleware.ValidateHalfWidthInput())
	r.Patch("/api/v1/attendance/:id", attendanceController.UpdateColumns, middleware.Authenticate(r.auth, auth.RoleAdmin), middleware.ValidateHalfWidthInput())
	r.Delete("/api/v1/attendance/:id", attendanceController.Delete, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/attendance", attendanceController.GetStatistics, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/attendance/piechart", attendanceController.GetPieChartStatistics, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/attendance/barchart", attendanceController.GetBarChartStatistics, middleware.Authenticate(r.auth, auth.RoleAdmin))
	r.Get("/api/v1/attendance/graph", attendanceController.GetGraphStatistic, middleware.Authenticate(r.auth, auth.RoleAdmin))

	return r.Run(r.port)
}
