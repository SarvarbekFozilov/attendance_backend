package user

import (
	"attendance/backend/foundation/web"
	"attendance/backend/internal/pkg/config"
	submodel "attendance/backend/internal/repository/postgres/sub_model"
	"attendance/backend/internal/repository/postgres/user"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/Azure/go-autorest/autorest/date"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/lib/pq" // PostgreSQL driver
)

type Controller struct {
	user         User
	company_Info CompanyInfo
}

func NewController(user User, company_Info CompanyInfo) *Controller {
	return &Controller{user, company_Info}
}

// user

func (uc Controller) GetUserList(c *web.Context) error {
	var filter user.Filter

	if limit, ok := c.GetQueryFunc(reflect.Int, "limit").(*int); ok {
		filter.Limit = limit
	}
	if offset, ok := c.GetQueryFunc(reflect.Int, "offset").(*int); ok {
		filter.Offset = offset
	}
	if page, ok := c.GetQueryFunc(reflect.Int, "page").(*int); ok {
		filter.Page = page
	}
	if search, ok := c.GetQueryFunc(reflect.String, "search").(*string); ok {
		filter.Search = search
	}
	if departmentId, ok := c.GetQueryFunc(reflect.Int, "department_id").(*int); ok {
		filter.DepartmentID = departmentId
	}
	if positionId, ok := c.GetQueryFunc(reflect.Int, "position_id").(*int); ok {
		filter.PositionID = positionId
	}
	if err := c.ValidQuery(); err != nil {
		return c.RespondError(err)
	}

	list, count, err := uc.user.GetList(c.Ctx, filter)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"data": map[string]interface{}{
			"results": list,
			"count":   count,
		},
		"status": true,
	}, http.StatusOK)
}

func (uc Controller) GetUserDetailById(c *web.Context) error {
	id := c.GetParam(reflect.Int, "id").(int)

	if err := c.ValidParam(); err != nil {
		return c.RespondError(err)
	}

	response, err := uc.user.GetDetailById(c.Ctx, id)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"data":   response,
		"status": true,
	}, http.StatusOK)
}
func (uc Controller) GetQrCodeByEmployeeId(c *web.Context) error {

	// Get the 'employee_id' query parameter
	employeeID := c.Query("employee_id")
	if employeeID == "" {
		return c.RespondError(web.NewRequestError(errors.New("employee_id parameter is required"), http.StatusBadRequest))
	}

	// Call the repository method to get the image file path
	filePath, err := uc.user.GetQrCodeByEmployeeID(c.Ctx, employeeID)
	if err != nil {
		return c.RespondError(err)
	}

	// Open the QR code image file
	file, err := os.Open(filePath)
	if err != nil {
		return c.RespondError(err)
	}
	defer file.Close()

	// Set the content type to PNG
	c.Header("Content-Type", "image/png")
	c.Header("Content-Disposition", "inline; filename="+filepath.Base(filePath))
	// Write the image data to the response
	c.Status(http.StatusOK)
	_, err = io.Copy(c.Writer, file)
	if err != nil {
		return c.RespondError(err)
	}

	return nil
}
func (uc Controller) GetQrCodeList(c *web.Context) error {
	// Generate the PDF containing QR codes for all employees
	pdfFilename, err := uc.user.GetQrCodeList(c.Ctx)
	if err != nil {
		return c.RespondError(err)
	}
	file, err := os.Open(pdfFilename)
	if err != nil {
		return c.RespondError(err)
	}
	defer file.Close()
	// Set the content type to PDF
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", "attachment; filename=\"qr_employees.pdf\"")
	// Write the PDF to the response
	_, err = io.Copy(c.Writer, file)
	if err != nil {
		return c.RespondError(err)
	}
	return nil
}
func (uc Controller) ExportEmployee(c *web.Context) error {
	// Generate the Excel file containing employee data
	xlsxFilename, err := uc.user.ExportEmployee(c.Ctx)
	if err != nil {
		return c.RespondError(err) // Handle any error from generating the Excel file
	}

	file, err := os.Open(xlsxFilename)
	if err != nil {
		return c.RespondError(err)
	}
	defer file.Close()

	// Set the content type for Excel files
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=\"employee_list.xlsx\"")

	_, err = io.Copy(c.Writer, file)
	if err != nil {
		return c.RespondError(err)
	}
	// os.Remove("employee_list.xlsx")
	return nil
}
func (uc Controller) ExportTemplate(c *web.Context) error {
	// Generate the Excel file containing employee data
	xlsxFilename, err := uc.user.ExportTemplate(c.Ctx)
	if err != nil {
		return c.RespondError(err) // Handle any error from generating the Excel file
	}

	file, err := os.Open(xlsxFilename)
	if err != nil {
		return c.RespondError(err)
	}
	defer file.Close()

	// Set the content type for Excel files
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=\"template.xlsx\"")

	_, err = io.Copy(c.Writer, file)
	if err != nil {
		return c.RespondError(err)
	}

	// os.Remove("template.xls")
	return nil
}

func (uc Controller) CreateUser(c *web.Context) error {
	var request user.CreateRequest
	if err := c.BindFunc(&request); err != nil {
		return c.RespondError(err)
	}
	response, err := uc.user.Create(c.Ctx, request)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"created_data": response,
		"status":       true,
	}, http.StatusOK)
}
func (uc Controller) CreateUserByExcell(c *web.Context) error {
	var request user.ExcellRequest
	if err := c.BindFunc(&request); err != nil {
		return c.RespondError(err)
	}

	var (
		count        int
		invalidUsers []submodel.InvalidUserResponse
		err          error
	)

	switch request.Mode {
	case 1: // Create mode
		count, invalidUsers, err = uc.user.CreateByExcell(c.Ctx, request)
	case 2: // Update mode
		count, _, err = uc.user.UpdateByExcell(c.Ctx, request)
	case 3: // Delete mode
		count, _, err = uc.user.DeleteByExcell(c.Ctx, request)
	default:
		return c.RespondError(errors.New("invalid mode specified"))
	}

	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"success_count": count,
		"status":        true,
		"invalid_users": invalidUsers,
	}, http.StatusOK)
}
func (uc Controller) UpdateUserColumns(c *web.Context) error {
	id := c.GetParam(reflect.Int, "id").(int)

	if err := c.ValidParam(); err != nil {
		return c.RespondError(err)
	}

	var request user.UpdateRequest

	if err := c.BindFunc(&request); err != nil {
		return c.RespondError(err)
	}

	request.ID = id

	err := uc.user.UpdateColumns(c.Ctx, request)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"data":   "ok!",
		"status": true,
	}, http.StatusOK)
}

func (uc Controller) DeleteUser(c *web.Context) error {
	id := c.GetParam(reflect.Int, "id").(int)

	if err := c.ValidParam(); err != nil {
		return c.RespondError(err)
	}

	err := uc.user.Delete(c.Ctx, id)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"data":   "ok!",
		"status": true,
	}, http.StatusOK)
}

func (uc Controller) GetStatistics(c *web.Context) error {
	var filter user.StatisticRequest
	// Get the 'month' query parameter
	monthStr := c.Query("month")
	if monthStr == "" {
		return c.RespondError(web.NewRequestError(errors.New("month parameter is required"), http.StatusBadRequest))
	}
	fmt.Println("Month", monthStr)
	parsedMonth, err := date.ParseDate(monthStr)
	if err != nil {
		return c.RespondError(web.NewRequestError(errors.New("invalid date format"), http.StatusBadRequest))
	}
	filter.Month = parsedMonth

	// Get the 'interval' query parameter
	intervalStr := c.Query("interval")
	if intervalStr == "" {
		return c.RespondError(web.NewRequestError(errors.New("interval parameter is required"), http.StatusBadRequest))
	}

	interval, err := strconv.Atoi(intervalStr)
	if err != nil {
		return c.RespondError(web.NewRequestError(errors.New("invalid interval format"), http.StatusBadRequest))
	}
	filter.Interval = interval
	list, err := uc.user.GetStatistics(c.Ctx, filter)
	if err != nil {
		return c.RespondError(err)
	}

	return c.Respond(map[string]interface{}{
		"data": map[string]interface{}{
			"results": list,
		},
		"status": true,
	}, http.StatusOK)
}

func (uc Controller) GetMonthlyStatistics(c *web.Context) error {
	var filter user.MonthlyStatisticRequest
	// Get the 'month' query parameter
	monthStr := c.Query("month")
	if monthStr == "" {
		return c.RespondError(web.NewRequestError(errors.New("month parameter is required"), http.StatusBadRequest))
	}
	parsedMonth, err := date.ParseDate(monthStr)
	if err != nil {
		return c.RespondError(web.NewRequestError(errors.New("invalid date format"), http.StatusBadRequest))
	}
	filter.Month = parsedMonth
	list, err := uc.user.GetMonthlyStatistics(c.Ctx, filter)
	if err != nil {
		return c.RespondError(err)
	}
	return c.Respond(map[string]interface{}{
		"data": map[string]interface{}{
			"results": list,
		},
		"status": true,
	}, http.StatusOK)
}

func (uc Controller) GetEmployeeDashboard(c *web.Context) error {

	if err := c.ValidParam(); err != nil {
		return c.RespondError(err)
	}

	response, err := uc.user.GetEmployeeDashboard(c.Ctx)
	if err != nil {
		return c.RespondError(err)
	}
	employee, err := uc.user.GetFullName(c.Ctx)
	if err != nil {
		return c.RespondError(err)
	}
	return c.Respond(map[string]interface{}{
		"employee":    employee.FullName,
		"employee_id": employee.EmployeeID,
		"data":        response,
		"status":      true,
	}, http.StatusOK)
}

var dbPool *pgxpool.Pool

func ConnectDB(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 1000 // Poolning maksimal hajmini oshirish
	pool, err := pgxpool.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

// GetDashboardListSSE streams data to the client via Server-Sent Events (SSE)
func (uc Controller) GetDashboardListSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	// Initialize database pool if not already done
	if dbPool == nil {
		yamlConfig, err := config.NewConfig()
		if err != nil {
			log.Printf("Error loading configuration: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		dsn := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
			yamlConfig.DBUsername, yamlConfig.DBPassword, yamlConfig.DBHost, yamlConfig.DBPort, yamlConfig.DBName)
		dbPool, err = ConnectDB(ctx, dsn)
		if err != nil {
			log.Printf("Database connection error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	dbConn, err := dbPool.Acquire(ctx)
	if err != nil {
		log.Printf("Failed to acquire database connection: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer dbConn.Release()

	// Start listening for database notifications
	_, err = dbConn.Exec(ctx, "LISTEN attendance_changes")
	if err != nil {
		log.Printf("Failed to set up LISTEN: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send initial data to the client
	go func() {
		var filter user.Filter
		// You can extract filters from the request query if needed

		list, count, err := uc.user.GetDashboardList(ctx, filter)
		if err != nil {
			log.Printf("Error fetching dashboard list: %v", err)
			return
		}
		colors, err := uc.company_Info.GetNewTableColor(ctx)
		if err != nil {
			log.Printf("Error fetching dashboard list: %v", err)
			return
		}

		data := map[string]interface{}{

			"bold": colors.TextBold,
			"Colors": map[string]interface{}{
				"new_present_color": colors.NewPresentColor,
				"new_absent_color":  colors.NewAbsentColor,
			},
			"data": map[string]interface{}{
				"results": list,
				"count":   count,
			},
			"status": true,
		}
		jsonData, _ := json.Marshal(data)

		// Send the data
		fmt.Fprintf(w, "data: %s\n\n", jsonData)
		flusher.Flush()
	}()

	// Wait for database notifications and send updates
	for {
		notification, err := dbConn.Conn().WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil { // Handle client disconnect
				log.Println("Client disconnected.")
				break
			}
			log.Printf("Error waiting for notification: %v", err)
			break
		}

		if notification.Channel == "attendance_changes" {
			log.Println("Attendance changed notification received.")

			var filter user.Filter
			// Add your filter setup here if needed

			list, count, err := uc.user.GetDashboardList(ctx, filter)
			if err != nil {
				log.Printf("Error fetching updated dashboard list: %v", err)
				continue
			}

			data := map[string]interface{}{
				"data": map[string]interface{}{
					"results": list,
					"count":   count,
				},
				"status": true,
			}
			jsonData, _ := json.Marshal(data)

			// Send the updated data
			fmt.Fprintf(w, "data: %s\n\n", jsonData)
			flusher.Flush()
		}
	}

	log.Println("SSE connection closed.")
}
